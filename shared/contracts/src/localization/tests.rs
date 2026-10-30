use super::{
    add_missing_baseline_coverage_warnings, build_effective_locale_bundles, bundled_locales_dir_in,
    fill_candidate, normalize_locale_id, read_locale_candidate, reject_fallback_cycles,
    require_metadata_string, resolve_catalog_text, sorted_unique_descriptors, strip_utf8_bom,
    tray_catalog_from, validate_candidate_root, validate_cross_locale_rules,
    validate_tray_candidates, LocaleCandidate, LocaleDescriptor, LocaleLoadStatus, LocaleSource,
    MAX_LOCALE_FALLBACKS, MAX_LOCALE_FILE_BYTES, MAX_LOCALE_KEY_BYTES, MAX_LOCALE_WARNINGS,
};

use serde_json::json;
use std::collections::BTreeMap;

#[test]
fn bundled_locales_are_never_taken_from_above_the_binary() {
    let root = tempfile::tempdir().expect("tempdir");
    let binary_dir = root.path().join("bin");
    std::fs::create_dir_all(root.path().join("locales")).expect("planted locales");
    std::fs::create_dir_all(&binary_dir).expect("binary dir");
    assert_eq!(bundled_locales_dir_in(Some(&binary_dir), None), None);

    std::fs::create_dir_all(binary_dir.join("locales")).expect("shipped locales");
    assert_eq!(
        bundled_locales_dir_in(Some(&binary_dir), Some(root.path())),
        Some(binary_dir.join("locales"))
    );
}

/// One malformed key must cost that key, not the language.
///
/// A structural failure inside a single entry used to be an error, and the
/// bundle builder drops any candidate with errors — so one typo among two
/// thousand keys silently switched the whole interface to English, with the
/// only signal an `eprintln!` in a process that has no console.
#[test]
fn one_malformed_key_does_not_cost_the_whole_locale() {
    let payload = r#"{
    "metadata": {
        "language": "ru",
        "label": "Russian",
        "nativeLabel": "Русский",
        "version": "1.0",
        "fallbacks": ["en"]
    },
    "menu": {
        "file": "Файл",
        "Bad_Segment": "не должен утащить файл",
        "quit": "Выход"
    },
    "status": { "ready": 42 }
}"#;
    let parsed: serde_json::Value = serde_json::from_str(payload).expect("fixture parses");
    let mut subject = candidate("ru", &["en"], &[]);
    subject.entries.clear();
    validate_candidate_root(&parsed, &mut subject);

    assert!(
        subject.errors.is_empty(),
        "a per-key defect must not be a file-level error: {:?}",
        subject.errors
    );
    assert_eq!(
        subject.entries.get("menu.file").map(String::as_str),
        Some("Файл")
    );
    assert_eq!(
        subject.entries.get("menu.quit").map(String::as_str),
        Some("Выход"),
        "keys after the bad one must survive"
    );
    assert!(
        !subject.entries.contains_key("menu.Bad_Segment"),
        "the malformed key itself must not be admitted"
    );
    assert!(
        !subject.entries.contains_key("status.ready"),
        "a non-string leaf must not be admitted"
    );
    assert!(
        subject.warnings.iter().any(|w| w.contains("Bad_Segment")),
        "the defect must still be reported: {:?}",
        subject.warnings
    );

    // Positive control: a file that cannot be parsed at all is still a
    // file-level error, so partial acceptance did not disarm the check.
    let mut broken = candidate("ru", &["en"], &[]);
    broken.entries.clear();
    validate_candidate_root(&serde_json::json!([1, 2, 3]), &mut broken);
    assert!(!broken.errors.is_empty());
}

/// A blank translation is a missing one: kept, it would shadow the English
/// fallback and draw an empty button.
#[test]
fn a_blank_translation_is_dropped_so_the_key_falls_back() {
    let parsed = json!({
        "metadata": {
            "language": "ru",
            "label": "Russian",
            "nativeLabel": "Русский",
            "version": "1.0",
            "fallbacks": ["en"]
        },
        "action": { "apply": "", "cancel": "  ", "close": "Закрыть" }
    });
    let mut subject = candidate("ru", &["en"], &[]);
    subject.entries.clear();
    validate_candidate_root(&parsed, &mut subject);

    assert!(subject.errors.is_empty(), "{:?}", subject.errors);
    assert!(!subject.entries.contains_key("action.apply"));
    assert!(!subject.entries.contains_key("action.cancel"));
    assert_eq!(
        subject.entries.get("action.close").map(String::as_str),
        Some("Закрыть")
    );
    assert!(
        subject.warnings.iter().any(|w| w.contains("action.apply")),
        "{:?}",
        subject.warnings
    );

    let mut en = BTreeMap::new();
    en.insert("action.apply".to_string(), "Apply".to_string());
    let mut catalog = BTreeMap::new();
    catalog.insert("en".to_string(), en);
    catalog.insert("ru".to_string(), subject.entries.clone());
    assert_eq!(
        resolve_catalog_text(&catalog, "ru", "action.apply", "fallback"),
        "Apply"
    );
}

/// A user override is a second FILE for a language the bundle already
/// ships, and the picker lists languages, not files.
#[test]
fn the_language_list_has_one_entry_per_language() {
    let ru = || LocaleDescriptor {
        id: "ru".to_string(),
        label: "Russian".to_string(),
        native_label: "Русский".to_string(),
        fallbacks: vec!["en".to_string()],
    };
    let en = LocaleDescriptor {
        id: "en".to_string(),
        label: "English".to_string(),
        native_label: "English".to_string(),
        fallbacks: Vec::new(),
    };
    let listed = sorted_unique_descriptors(vec![ru(), en.clone(), ru()]);
    let ids: Vec<&str> = listed.iter().map(|d| d.id.as_str()).collect();
    assert_eq!(ids, vec!["en", "ru"]);

    // Positive control: two DIFFERENT languages are both kept.
    let listed = sorted_unique_descriptors(vec![ru(), en]);
    assert_eq!(listed.len(), 2);
}

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

/// The validator is the only definition of a well-formed locale file, so the
/// shipped locales and the example handed to translators must pass it clean:
/// no error, and no warning (a warning means a key was ignored).
#[test]
fn shipped_locales_and_the_translator_example_pass_the_validator_clean() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let scratch = tempfile::tempdir().expect("tempdir");
    // The locale id comes from the file name, so the example is judged as the
    // `en.json` a translator would save it as.
    let example = scratch.path().join("en.json");
    std::fs::copy(
        repo.join("configs/localization/locale.v1.example.json"),
        &example,
    )
    .expect("copy example");

    for path in [
        repo.join("locales/en.json"),
        repo.join("locales/ru.json"),
        repo.join("locales/tray/en.json"),
        repo.join("locales/tray/ru.json"),
        example,
    ] {
        let candidate = read_locale_candidate(&path, LocaleSource::Bundled)
            .unwrap_or_else(|| panic!("{} is not read as a locale", path.display()));
        assert!(
            candidate.errors.is_empty() && candidate.warnings.is_empty(),
            "{}: errors {:?}, warnings {:?}",
            path.display(),
            candidate.errors,
            candidate.warnings
        );
    }
}

fn locale_text(id: &str, fallbacks: &str, body: &str) -> String {
    format!(
        r#"{{"metadata": {{"language": "{id}", "label": "L", "nativeLabel": "L", "version": "1.0", "fallbacks": {fallbacks}}}, {body}}}"#
    )
}

/// A file in the user's folder is anyone's bytes: past the bound it is not
/// read, the refusal is reported, and the language keeps its bundled text.
#[test]
fn an_oversized_user_locale_is_refused_and_the_bundled_one_stays() {
    let padding = "x".repeat(MAX_LOCALE_FILE_BYTES);
    let body = format!(r#""menu": {{"file": "{padding}"}}"#);
    let (_dir, path) = write_temp_locale(&locale_text("ru", r#"["en"]"#, &body));
    let user = read_locale_candidate(&path, LocaleSource::User).expect("candidate");
    assert_eq!(user.status(), LocaleLoadStatus::Rejected);
    assert!(
        user.errors.iter().any(|e| e.contains("larger than")),
        "{:?}",
        user.errors
    );
    assert!(user.entries.is_empty());

    let bundled = candidate("ru", &["en"], &[("menu.file", "Файл")]);
    let bundles = build_effective_locale_bundles(&[bundled, user]);
    let ru = bundles.iter().find(|b| b.id == "ru").expect("ru stays");
    assert_eq!(
        ru.entries.get("menu.file").map(String::as_str),
        Some("Файл")
    );

    // The bound itself is a size, not a guess from the file system: bytes
    // handed over past it are refused the same way.
    let mut subject = candidate("ru", &["en"], &[]);
    subject.entries.clear();
    fill_candidate(&mut subject, vec![b' '; MAX_LOCALE_FILE_BYTES + 1]);
    assert_eq!(subject.status(), LocaleLoadStatus::Rejected);
}

#[test]
fn a_locale_path_that_is_not_a_file_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("ru.json");
    std::fs::create_dir(&path).expect("directory named like a locale");
    let subject = read_locale_candidate(&path, LocaleSource::User).expect("candidate");
    assert_eq!(subject.status(), LocaleLoadStatus::Rejected);
}

/// Each bad key costs one warning line until the list is full; then one line
/// says so. The good keys are kept either way.
#[test]
fn a_flood_of_bad_keys_cannot_grow_the_report() {
    let bad: Vec<String> = (0..500).map(|i| format!(r#""Bad_{i}": "x""#)).collect();
    let long_key = "k".repeat(MAX_LOCALE_KEY_BYTES);
    let body = format!(
        r#""menu": {{"file": "File", {}, "{long_key}": "x"}}"#,
        bad.join(", ")
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&locale_text("ru", r#"["en"]"#, &body)).expect("fixture parses");
    let mut subject = candidate("ru", &["en"], &[]);
    subject.entries.clear();
    validate_candidate_root(&parsed, &mut subject);
    assert!(subject.errors.is_empty(), "{:?}", subject.errors);
    assert_eq!(subject.warnings.len(), MAX_LOCALE_WARNINGS + 1);
    assert_eq!(
        subject.warnings.last().map(String::as_str),
        Some("further warnings are not listed")
    );
    assert_eq!(
        subject.entries.get("menu.file").map(String::as_str),
        Some("File")
    );
    assert_eq!(
        subject.entries.len(),
        1,
        "the over-long key is not admitted"
    );
}

#[test]
fn an_over_long_key_is_ignored_and_reported() {
    let long_key = "k".repeat(MAX_LOCALE_KEY_BYTES);
    let body = format!(r#""menu": {{"file": "File", "{long_key}": "x"}}"#);
    let parsed: serde_json::Value =
        serde_json::from_str(&locale_text("ru", r#"["en"]"#, &body)).expect("fixture parses");
    let mut subject = candidate("ru", &["en"], &[]);
    subject.entries.clear();
    validate_candidate_root(&parsed, &mut subject);
    assert_eq!(subject.status(), LocaleLoadStatus::AcceptedWithWarnings);
    assert_eq!(subject.entries.len(), 1);
    assert!(
        subject.warnings.iter().any(|w| w.contains("longer than")),
        "{:?}",
        subject.warnings
    );
}

/// The fallback chain is metadata, and metadata this broken drops the file.
#[test]
fn a_fallback_list_past_the_bound_is_broken_metadata() {
    let many: Vec<String> = (0..=MAX_LOCALE_FALLBACKS)
        .map(|i| format!(r#""x{i}""#))
        .collect();
    let fallbacks = format!("[{}]", many.join(", "));
    let parsed: serde_json::Value = serde_json::from_str(&locale_text(
        "ru",
        &fallbacks,
        r#""menu": {"file": "File"}"#,
    ))
    .expect("fixture parses");
    let mut subject = candidate("ru", &["en"], &[]);
    subject.entries.clear();
    validate_candidate_root(&parsed, &mut subject);
    assert_eq!(subject.status(), LocaleLoadStatus::Rejected);
}

/// The bound must stay far above what ships, or a growing translation would
/// one day drop a whole language.
#[test]
fn shipped_locales_stay_well_under_the_size_bound() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for name in ["locales/en.json", "locales/ru.json"] {
        let len = std::fs::metadata(repo.join(name))
            .expect("shipped locale")
            .len();
        let bound = u64::try_from(MAX_LOCALE_FILE_BYTES / 2).expect("fits");
        assert!(
            len < bound,
            "{name} is {len} bytes, half the bound is {bound}"
        );
    }
}

fn tray_fixture() -> (Vec<LocaleCandidate>, Vec<LocaleCandidate>) {
    let main = vec![
        candidate(
            "en",
            &[],
            &[("action.close", "Close"), ("settings.title", "Settings")],
        ),
        candidate(
            "ru",
            &["en"],
            &[("action.close", "Закрыть"), ("settings.title", "Настройки")],
        ),
        candidate("de", &["en"], &[("action.close", "Schließen")]),
    ];
    let tray = vec![
        candidate("en", &[], &[("tray.menu.title", "Menu")]),
        candidate("ru", &["en"], &[("tray.menu.title", "Меню")]),
    ];
    (main, tray)
}

/// The tray is handed its own language and English, never the window's other
/// words or another language: each one costs the tray process memory.
#[test]
fn the_tray_catalogue_holds_its_language_and_english_only() {
    let (main, tray) = tray_fixture();
    let catalog = tray_catalog_from(&main, &tray, "ru_RU.UTF-8", &["action."]);
    assert_eq!(
        catalog.keys().map(String::as_str).collect::<Vec<_>>(),
        ["en", "ru"]
    );
    let ru = &catalog["ru"];
    assert_eq!(ru.get("tray.menu.title").map(String::as_str), Some("Меню"));
    assert_eq!(ru.get("action.close").map(String::as_str), Some("Закрыть"));
    assert!(!ru.contains_key("settings.title"), "{ru:?}");
    assert!(!catalog["en"].contains_key("settings.title"));
    assert_eq!(
        catalog["en"].get("tray.menu.title").map(String::as_str),
        Some("Menu")
    );

    let english_only = tray_catalog_from(&main, &tray, "en", &["action."]);
    assert_eq!(english_only.keys().collect::<Vec<_>>(), ["en"]);
    let unknown = tray_catalog_from(&main, &tray, "fr", &["action."]);
    assert_eq!(unknown.keys().collect::<Vec<_>>(), ["en"]);
}

/// A language without a tray file still shows the window's words in itself,
/// and the tray's own words in English through the per-key fallback.
#[test]
fn a_language_without_a_tray_file_shows_the_tray_words_in_english() {
    let (main, tray) = tray_fixture();
    let catalog = tray_catalog_from(&main, &tray, "de", &["action.close"]);
    let de = &catalog["de"];
    assert_eq!(
        de.get("action.close").map(String::as_str),
        Some("Schließen")
    );
    assert!(!de.contains_key("tray.menu.title"));
    assert_eq!(
        resolve_catalog_text(&catalog, "de", "tray.menu.title", "raw"),
        "Menu"
    );
}

/// The user's tray file outranks the shipped one key by key, as the main
/// files do; keys it does not name keep the shipped text.
#[test]
fn a_user_tray_file_outranks_the_shipped_one_per_key() {
    let (main, mut tray) = tray_fixture();
    tray[1]
        .entries
        .insert("tray.menu.quit".to_string(), "Выход".to_string());
    tray.push(candidate_with_source(
        "ru",
        LocaleSource::User,
        &["en"],
        &[("tray.menu.title", "Моё меню")],
    ));
    let catalog = tray_catalog_from(&main, &tray, "ru", &[]);
    assert_eq!(
        catalog["ru"].get("tray.menu.title").map(String::as_str),
        Some("Моё меню")
    );
    assert_eq!(
        catalog["ru"].get("tray.menu.quit").map(String::as_str),
        Some("Выход")
    );
}

/// A language is found by its main file only: a tray file alone adds none.
#[test]
fn a_tray_file_without_its_main_file_is_not_used() {
    let (main, mut tray) = tray_fixture();
    tray.push(candidate("fr", &["en"], &[("tray.menu.title", "Menu FR")]));
    validate_tray_candidates(&mut tray, &main);
    let french = tray.iter().find(|c| c.id == "fr").expect("fr");
    assert_eq!(french.status(), LocaleLoadStatus::Rejected);
    let catalog = tray_catalog_from(&main, &tray, "fr", &[]);
    assert_eq!(catalog.keys().collect::<Vec<_>>(), ["en"]);
    assert!(tray
        .iter()
        .filter(|c| c.id != "fr")
        .all(|c| c.errors.is_empty()));
}
