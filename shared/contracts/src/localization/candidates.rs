// Reading locale files off disk into unvalidated candidates.

use super::bundles::*;
use super::validation::*;
use super::*;

use std::io::Read;

pub(super) fn sorted_unique_descriptors(
    mut descriptors: Vec<LocaleDescriptor>,
) -> Vec<LocaleDescriptor> {
    descriptors.sort_by(|left, right| left.id.cmp(&right.id));
    descriptors.dedup_by(|left, right| left.id == right.id);
    descriptors
}

pub(super) fn load_locale_candidates() -> Vec<LocaleCandidate> {
    load_locale_candidates_in(None)
}

/// The tray files, `tray/<id>.json` under each locales folder, named by that
/// path in reports.
pub(super) fn load_tray_locale_candidates() -> Vec<LocaleCandidate> {
    let mut candidates = load_locale_candidates_in(Some(TRAY_SUBFOLDER));
    for candidate in &mut candidates {
        candidate.file_name = format!("{TRAY_SUBFOLDER}/{}", candidate.file_name);
    }
    candidates
}

fn load_locale_candidates_in(subfolder: Option<&str>) -> Vec<LocaleCandidate> {
    let within = |dir: PathBuf| match subfolder {
        Some(name) => dir.join(name),
        None => dir,
    };
    let bundled_dir = resolve_bundled_locales_dir().map(within);
    let user_dir = resolve_user_locales_dir().map(within);
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
        .take(MAX_LOCALE_FILES_PER_DIR)
        .collect::<Vec<_>>()
}

pub(super) fn read_locale_candidate(path: &Path, source: LocaleSource) -> Option<LocaleCandidate> {
    if !path.extension()?.to_str()?.eq_ignore_ascii_case("json") {
        return None;
    }

    let stem = path.file_stem()?.to_str()?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_string();
    let mut candidate = new_candidate(stem, file_name, source);
    match read_bounded(path) {
        Ok(bytes) => fill_candidate(&mut candidate, bytes),
        Err(error) => candidate.errors.push(error),
    }
    Some(candidate)
}

/// A candidate for the file named `stem`, nothing read into it yet.
pub(super) fn new_candidate(
    stem: &str,
    file_name: String,
    source: LocaleSource,
) -> LocaleCandidate {
    let id = normalize_locale_id(stem);
    LocaleCandidate {
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
    }
}

/// At most one byte past [`MAX_LOCALE_FILE_BYTES`], so an oversized file is
/// told apart without being read whole. Only a regular file: a pipe or a
/// device planted under a `.json` name would never end.
fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let failed = |error: std::io::Error| format!("failed to read locale file: {error}");
    let metadata = fs::metadata(path).map_err(failed)?;
    if !metadata.is_file() {
        return Err("locale path is not a regular file".to_string());
    }
    let limit = u64::try_from(MAX_LOCALE_FILE_BYTES).unwrap_or(u64::MAX);
    if metadata.len() > limit {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(limit.saturating_add(1)).read_to_end(&mut bytes))
        .map_err(failed)?;
    Ok(bytes)
}

fn too_large() -> String {
    format!("locale file is larger than {MAX_LOCALE_FILE_BYTES} bytes and is not read")
}

/// Decodes, parses and validates one file's bytes into `candidate`.
pub(super) fn fill_candidate(candidate: &mut LocaleCandidate, raw_bytes: Vec<u8>) {
    if raw_bytes.len() > MAX_LOCALE_FILE_BYTES {
        candidate.errors.push(too_large());
        return;
    }
    let bom_present = raw_bytes.starts_with(&[0xEF, 0xBB, 0xBF]);
    let raw = match String::from_utf8(raw_bytes) {
        Ok(text) => text,
        Err(error) => {
            candidate
                .errors
                .push(format!("invalid UTF-8 in locale file: {error}"));
            return;
        }
    };

    if bom_present {
        candidate
            .warnings
            .push("UTF-8 BOM was detected and ignored".to_string());
    }

    // serde_json stops at 128 levels of nesting, so the walk below is as deep.
    let parsed = match serde_json::from_str::<serde_json::Value>(strip_utf8_bom(&raw)) {
        Ok(value) => value,
        Err(error) => {
            candidate.errors.push(format!("invalid JSON: {error}"));
            return;
        }
    };

    validate_candidate_root(&parsed, candidate);
}
