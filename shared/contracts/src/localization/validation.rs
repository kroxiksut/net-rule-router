// Validating a candidate: metadata, key shape, and the rules that only make
// sense across the whole set (duplicate ids, fallback cycles, coverage).

use super::bundles::*;
use super::*;

pub(super) fn validate_candidate_root(value: &serde_json::Value, candidate: &mut LocaleCandidate) {
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

pub(super) fn validate_metadata(
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
                    // Not a defect, and not worth telling anyone about: the
                    // schema refuses an EMPTY `fallbacks`, so the baseline
                    // locale — which has nothing to fall back to — can only be
                    // spelled as a self-reference. The chain ignores it. It was
                    // reported as a warning on every single launch, which is
                    // noise the user can neither act on nor silence.
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

pub(super) fn require_metadata_string(
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

pub(super) fn require_metadata_string_array(
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

pub(super) fn flatten_locale_object_validated(
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
            candidate.warnings.push(format!(
                "reserved namespace '{key}' is not allowed in locale translation payload;                  the namespace is ignored"
            ));
            continue;
        }

        // One bad segment costs one key, never the file. This used to push an
        // error, and a single typo among two thousand keys dropped the whole
        // locale to English with no signal a user could see. Structural
        // failures below stay errors; this is a defect in one entry.
        if !is_valid_key_segment(key) {
            candidate.warnings.push(format!(
                "invalid key segment '{key}' in namespace '{}'; the key is ignored",
                if prefix.is_empty() { "<root>" } else { prefix }
            ));
            continue;
        }

        let merged_key = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };

        if is_root && !nested.is_object() {
            candidate.warnings.push(format!(
                "root translation key '{key}' must be a namespace object; it is ignored"
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

        candidate.warnings.push(format!(
            "translation key '{merged_key}' has invalid value type; only string/object are              allowed, so the key is ignored"
        ));
    }
}

pub(super) fn validate_cross_locale_rules(candidates: &mut [LocaleCandidate]) {
    mark_duplicate_locale_ids(candidates);
    sanitize_fallback_targets(candidates);
    reject_fallback_cycles(candidates);
}

pub(super) fn mark_duplicate_locale_ids(candidates: &mut [LocaleCandidate]) {
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

pub(super) fn sanitize_fallback_targets(candidates: &mut [LocaleCandidate]) {
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

pub(super) fn reject_fallback_cycles(candidates: &mut [LocaleCandidate]) {
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

pub(super) fn dfs_collect_cycles(
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

pub(super) fn add_missing_baseline_coverage_warnings(candidates: &mut [LocaleCandidate]) {
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
