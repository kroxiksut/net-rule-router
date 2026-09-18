// Reading locale files off disk into unvalidated candidates.

use super::bundles::*;
use super::validation::*;
use super::*;

pub(super) fn sorted_unique_descriptors(
    mut descriptors: Vec<LocaleDescriptor>,
) -> Vec<LocaleDescriptor> {
    descriptors.sort_by(|left, right| left.id.cmp(&right.id));
    descriptors.dedup_by(|left, right| left.id == right.id);
    descriptors
}

pub(super) fn load_locale_candidates() -> Vec<LocaleCandidate> {
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

pub(super) fn load_locale_candidates_from_dir(
    path: PathBuf,
    source: LocaleSource,
) -> Vec<LocaleCandidate> {
    fs::read_dir(path)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter_map(|entry| read_locale_candidate(&entry.path(), source))
        .collect::<Vec<_>>()
}

pub(super) fn read_locale_candidate(path: &Path, source: LocaleSource) -> Option<LocaleCandidate> {
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
