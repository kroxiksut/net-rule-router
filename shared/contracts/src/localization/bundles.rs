// Turning validated candidates into effective bundles: locale directories,
// fallback merge, and the diagnostics emitted about the load.

use super::*;

pub(super) fn build_effective_locale_bundles(
    candidates: &[LocaleCandidate],
) -> Vec<EffectiveLocaleBundle> {
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

pub(super) fn resolve_bundled_locales_dir() -> Option<PathBuf> {
    if let Ok(explicit_dir) = env::var("NRR_BUNDLED_LOCALES_DIR") {
        let path = PathBuf::from(explicit_dir);
        if path.exists() {
            return Some(path);
        }
    }

    let executable_dir = env::current_exe()
        .ok()
        .and_then(|executable| executable.parent().map(Path::to_path_buf));
    // `shared/contracts` sits two levels below the checkout root; the path is
    // the build machine's, so only a debug build trusts it.
    #[cfg(debug_assertions)]
    let checkout = Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2);
    #[cfg(not(debug_assertions))]
    let checkout = None;
    bundled_locales_dir_in(executable_dir.as_deref(), checkout)
}

/// Beside the binary, then the checkout — never a parent directory or the
/// working directory, where another local user can plant a `locales` folder.
pub(super) fn bundled_locales_dir_in(
    executable_dir: Option<&Path>,
    checkout: Option<&Path>,
) -> Option<PathBuf> {
    executable_dir
        .into_iter()
        .chain(checkout)
        .map(|root| root.join("locales"))
        .find(|candidate| candidate.is_dir())
}

pub(super) fn resolve_user_locales_dir() -> Option<PathBuf> {
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

pub(super) fn resolve_managed_locales_dir() -> Option<PathBuf> {
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

pub(super) fn canonical_eq(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left_canonical), Ok(right_canonical)) => left_canonical == right_canonical,
        _ => left == right,
    }
}

pub(super) fn merge_missing_entries(
    target: &mut BTreeMap<String, String>,
    fallback: &BTreeMap<String, String>,
) {
    for (key, value) in fallback {
        target.entry(key.clone()).or_insert_with(|| value.clone());
    }
}

pub(super) fn normalize_locale_id(value: &str) -> String {
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

pub(super) fn strip_utf8_bom(value: &str) -> &str {
    value.strip_prefix('\u{feff}').unwrap_or(value)
}

pub(super) fn is_valid_key_segment(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

pub(super) fn default_locale_label(id: &str) -> String {
    match id {
        "en" => "English".to_string(),
        "ru" => "Russian".to_string(),
        _ => id.to_ascii_uppercase(),
    }
}

pub(super) fn default_locale_native_label(id: &str) -> String {
    match id {
        "en" => "English".to_string(),
        "ru" => "Русский".to_string(),
        _ => id.to_string(),
    }
}

pub(super) fn report_missing_key(language_id: &str, key: &str) {
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

pub(super) fn emit_locale_reports(reports: &[LocaleLoadReport]) {
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
