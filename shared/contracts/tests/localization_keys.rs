use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

const ALLOWED_TOP_LEVEL_DOMAINS: &[&str] = &[
    "menu",
    "section",
    "action",
    "settings",
    "dialog",
    "tray",
    "a11y",
    "label",
    "status",
    "interfaces",
    "rules",
    "diagnostics",
    "diag",
    "logs",
    "audit",
    "first-run",
    "theme",
    // Sanctioned root domains that accreted over time but were never added
    // to the allowlist, leaving this gate red. They are all live, in-use
    // top-level families.
    "connection",
    "errors",
    "mutations",
    "progress",
    "risk",
    // One wording per concept for the two route names, shared by every
    // surface that used to spell them itself.
    "route",
    "routing",
    "toast",
    "unsaved-changes",
    // Notifications centre (footer bell chip + NotificationCenterPopup) —
    // a live top-level family.
    "notifications",
    // VPN-client onboarding dialog (VpnOnboardingDialog). A live top-level
    // family; the workspace-wide locale gate was not run when it was added,
    // so it stayed off the allowlist.
    "vpn-onboarding",
    // Application-group routing dialog (AppGroupRoutingDialog): VMs/emulators
    // and P2P apps found on this machine. Same story as `vpn-onboarding`
    // above — the family shipped before this gate was re-run, so it was
    // missing from the allowlist.
    "app-groups",
    // Block-notification reason slugs, resolved by name from the tray and the
    // per-reason mute settings.
    "block-reason",
    // Capabilities this OS lacks, resolved by the slugs the service reports
    // (`platform.missing.<slug>.*`).
    "platform",
    // Texts only the terminal interface (`nrr-tui`) shows; shared concepts
    // reuse the families above.
    "tui",
];

/// Desktop Rust files that resolve locale keys at runtime. The QML and TUI
/// trees are walked instead: a hand-picked file stood for a tree that holds
/// most of its keys elsewhere.
const RUNTIME_KEY_SOURCE_FILES: &[&str] = &[
    "apps/desktop/gui/src/ui_surface.rs",
    // lib.rs because nrr-desktop-tray is a lib-only crate consumed by the launcher.
    "apps/desktop/tray/src/lib.rs",
    // The launcher's own notice when the Qt host cannot load its libraries.
    "apps/desktop/launcher/src/launcher/host_start_failure/mod.rs",
];

/// Trees walked recursively for keys, with the extensions read in each: the
/// QML files and their JavaScript libraries, and every terminal-interface module.
const RUNTIME_KEY_TREES: [(&str, &[&str]); 2] = [
    ("apps/desktop/qml", &["qml", "js"]),
    ("apps/tui/src", &["rs"]),
];

/// Every tree with crates that log: a tagged line outside `core/` reaches the
/// Logs view all the same.
const LOG_SOURCE_ROOTS: [&str; 3] = ["apps", "core", "shared"];

#[test]
fn locale_files_have_no_namespace_conflicts_or_invalid_leaf_types() {
    for locale_file in locale_files() {
        let raw = fs::read_to_string(&locale_file)
            .unwrap_or_else(|error| panic!("failed to read '{}': {error}", locale_file.display()));
        let parsed = serde_json::from_str::<Value>(raw.trim_start_matches('\u{feff}'))
            .unwrap_or_else(|error| {
                panic!(
                    "failed to parse locale JSON '{}': {error}",
                    locale_file.display()
                )
            });
        let root = parsed
            .as_object()
            .unwrap_or_else(|| panic!("root must be object: '{}'", locale_file.display()));

        assert!(
            root.contains_key("metadata"),
            "locale must include metadata block: '{}'",
            locale_file.display()
        );

        let mut leaf_keys = HashSet::new();
        let mut namespace_keys = HashSet::new();
        let mut errors = Vec::new();
        visit_locale_node(
            &parsed,
            "",
            true,
            &mut leaf_keys,
            &mut namespace_keys,
            &mut errors,
        );
        assert!(
            errors.is_empty(),
            "locale '{}' has structural issues:\n{}",
            locale_file.display(),
            errors.join("\n")
        );
    }
}

#[test]
fn locale_root_domains_use_fixed_allowlist() {
    let allowed = ALLOWED_TOP_LEVEL_DOMAINS
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    for locale_file in locale_files() {
        let raw = fs::read_to_string(&locale_file)
            .unwrap_or_else(|error| panic!("failed to read '{}': {error}", locale_file.display()));
        let parsed = serde_json::from_str::<Value>(raw.trim_start_matches('\u{feff}'))
            .unwrap_or_else(|error| {
                panic!(
                    "failed to parse locale JSON '{}': {error}",
                    locale_file.display()
                )
            });
        let root = parsed
            .as_object()
            .unwrap_or_else(|| panic!("root must be object: '{}'", locale_file.display()));

        let unexpected = root
            .keys()
            .filter(|key| key.as_str() != "metadata")
            .filter(|key| !allowed.contains(key.as_str()))
            .cloned()
            .collect::<Vec<_>>();

        assert!(
            unexpected.is_empty(),
            "locale '{}' has unexpected root domains: {}",
            locale_file.display(),
            unexpected.join(", ")
        );
    }
}

/// Checked against each bundled file as written: the loaded catalogue fills a
/// missing RU key from EN, so it would hide exactly the gap this looks for.
#[test]
fn runtime_uses_known_localization_keys() {
    let runtime_keys = collect_runtime_locale_keys();
    for locale in BASELINE_LOCALES {
        let known_keys = raw_locale_map(locale);
        let unknown = runtime_keys
            .iter()
            .filter(|key| !known_keys.contains_key(*key) && !is_allowed_runtime_dynamic_key(key))
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            unknown.is_empty(),
            "locale '{locale}' lacks localization keys the runtime uses: {}",
            unknown.join(", ")
        );
    }

    let deprecated = collect_runtime_locale_keys()
        .into_iter()
        .filter(|key| key.starts_with("common."))
        .collect::<Vec<_>>();
    assert!(
        deprecated.is_empty(),
        "runtime contains deprecated localization key families: {}",
        deprecated.join(", ")
    );
}

/// The terminal words its elevation refusal through a key it picks per host,
/// so both hosts' keys must exist in every baseline locale.
#[test]
fn the_terminal_elevation_refusal_is_worded_for_every_host() {
    let keys = [
        "errors.terminal-needs-elevation-unix",
        "errors.terminal-needs-elevation-windows",
    ];
    let host_key = nrr_shared::ipc_transport::terminal_needs_elevation_locale_key();
    assert!(keys.contains(&host_key));
    for locale in BASELINE_LOCALES {
        let map = raw_locale_map(locale);
        for key in keys {
            assert!(
                map.get(key).is_some_and(|text| !text.is_empty()),
                "locale '{locale}' lacks {key}"
            );
        }
    }
}

/// Both clients word a less certain offer's basis through a key built from
/// its slug, so every slug the service can send needs one in every locale.
#[test]
fn every_less_certain_basis_is_worded() {
    for locale in BASELINE_LOCALES {
        let map = raw_locale_map(locale);
        for slug in nrr_shared::ipc_payloads::AUTO_RULE_LESS_CERTAIN_SLUGS {
            let key = format!("rules.suggestions.less-certain.{slug}");
            assert!(
                map.get(&key).is_some_and(|text| text.contains("{site}")),
                "locale '{locale}' lacks {key}, or it does not name the site"
            );
        }
    }
}

/// A path that names no program says why, by its error's slug.
#[test]
fn every_path_error_is_worded() {
    for locale in BASELINE_LOCALES {
        let map = raw_locale_map(locale);
        for error in nrr_shared::app_path::AppPathError::ALL {
            let key = format!("rules.validation.match-value-invalid.{}", error.slug());
            assert!(map.contains_key(&key), "locale '{locale}' lacks {key}");
        }
    }
}

/// Both clients show an audit entry's cause through a key built from its slug.
#[test]
fn every_audit_cause_is_worded() {
    for locale in BASELINE_LOCALES {
        let map = raw_locale_map(locale);
        for slug in nrr_shared::diagnostics_dto::AUDIT_CAUSES {
            let key = format!("audit.cause.{slug}");
            assert!(
                map.get(&key).is_some_and(|text| !text.is_empty()),
                "locale '{locale}' lacks {key}"
            );
        }
    }
}

/// A service line tagged `msg_key = "<id>"` is shown in the Logs view as
/// `diag.event.<id>`; a tag with no translation would show English in RU.
#[test]
fn every_service_message_key_is_translated() {
    let mut tags = BTreeSet::new();
    for content in &log_sources() {
        for line in content.lines() {
            let line = line.trim_start();
            if line.starts_with("//") {
                continue;
            }
            let mut rest = line;
            while let Some(at) = rest.find("msg_key = \"") {
                rest = &rest[at + "msg_key = \"".len()..];
                let Some(end) = rest.find('"') else { break };
                tags.insert(rest[..end].to_string());
                rest = &rest[end..];
            }
        }
    }
    assert!(
        tags.len() >= 10,
        "found only {} msg_key tags — the scan is not seeing the call sites",
        tags.len()
    );

    for locale in BASELINE_LOCALES {
        let map = raw_locale_map(locale);
        let missing: Vec<_> = tags
            .iter()
            .filter(|tag| {
                !is_valid_key_segment(tag) || !map.contains_key(&format!("diag.event.{tag}"))
            })
            .collect();
        assert!(
            missing.is_empty(),
            "locale '{locale}' lacks diag.event.* for msg_key tags (or a tag is not kebab-case): {missing:?}"
        );
    }
}

/// The Logs view shows a tagged line's locale text, so a value spliced into the
/// English text never reaches it: values travel as fields, and an `error` field
/// has a `{error}` slot to land in.
#[test]
fn a_translated_log_line_keeps_its_values() {
    let sources = log_sources();
    let english = raw_locale_map("en");
    let mut sites = 0;
    let mut spliced = Vec::new();
    let mut unshown = Vec::new();
    for call in sources.iter().flat_map(|source| tagged_log_calls(source)) {
        sites += 1;
        if call.splices_values() {
            spliced.push(format!("{}: {}", call.key, call.text));
        }
        let text = english.get(&format!("diag.event.{}", call.key));
        if call.fields.iter().any(|field| field == "error")
            && !text.is_some_and(|text| text.contains("{error}"))
        {
            unshown.push(call.key);
        }
    }
    assert!(
        sites >= 400,
        "found only {sites} tagged log calls — the scan is not seeing them"
    );
    assert!(
        spliced.is_empty(),
        "tagged log lines splice values into their text instead of a field:\n{}",
        spliced.join("\n")
    );
    assert!(
        unshown.is_empty(),
        "diag.event.* texts lack `{{error}}` although the line carries an `error` field: {unshown:?}"
    );
}

#[test]
fn log_call_scan_reads_fields_text_and_trailing_args() {
    let source = r#"
        tracing::warn!(
            target: "nrr::x",
            msg_key = "x-failed",
            // a comment, with a comma
            count = 3,
            ?reason,
            error = %e,
            "could not do it: {}",
            e,
        );
        tracing::info!(msg_key = "x-picked", "{reason}");
    "#;
    let calls = tagged_log_calls(source);
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].key, "x-failed");
    assert_eq!(calls[0].fields, ["msg_key", "count", "reason", "error"]);
    assert!(calls[0].splices_values());
    assert!(!calls[1].splices_values());
}

/// One `trace!`..`error!` call that carries a `msg_key`.
struct TaggedLogCall {
    key: String,
    fields: Vec<String>,
    text: String,
    trailing_args: usize,
}

impl TaggedLogCall {
    /// Whether the English text interpolates anything. A text that is one
    /// capture and nothing else is picked whole from constants, so the
    /// translation loses nothing.
    fn splices_values(&self) -> bool {
        let inner = self.text.trim_matches('"');
        let captures = inner.replace("{{", "").matches('{').count();
        let picked_whole = captures == 1
            && inner.starts_with('{')
            && inner.ends_with('}')
            && inner[1..inner.len() - 1]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');
        self.trailing_args > 0 || (captures > 0 && !picked_whole)
    }
}

fn tagged_log_calls(source: &str) -> Vec<TaggedLogCall> {
    const MACROS: [&str; 5] = ["trace!(", "debug!(", "info!(", "warn!(", "error!("];
    let mut calls = Vec::new();
    let mut from = 0;
    while let Some((at, len)) = MACROS
        .iter()
        .filter_map(|m| source[from..].find(m).map(|i| (from + i, m.len())))
        .min()
    {
        from = at + len;
        let line_start = source[..at].rfind('\n').map_or(0, |i| i + 1);
        let is_word = source[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_');
        if is_word || source[line_start..at].trim_start().starts_with("//") {
            continue;
        }
        let Some(args) = macro_args(&source[from..]) else {
            continue;
        };
        let mut call = TaggedLogCall {
            key: String::new(),
            fields: Vec::new(),
            text: String::new(),
            trailing_args: 0,
        };
        for arg in args {
            if !call.text.is_empty() {
                call.trailing_args += 1;
                continue;
            }
            if arg.starts_with('"') {
                call.text = arg;
                continue;
            }
            if ["target:", "parent:", "name:"]
                .iter()
                .any(|p| arg.starts_with(p))
            {
                continue;
            }
            if let Some((name, value)) = arg
                .split_once('=')
                .filter(|(name, value)| !name.contains(['(', '"']) && !value.starts_with('='))
            {
                let name = name.trim().to_string();
                if name == "msg_key" {
                    call.key = value.trim().trim_matches('"').to_string();
                }
                call.fields.push(name);
            } else {
                let path = arg.trim_start_matches(['%', '?']);
                let name = path.rsplit(['.', ':']).next().unwrap_or(path);
                call.fields.push(name.to_string());
            }
        }
        if !call.key.is_empty() {
            calls.push(call);
        }
    }
    calls
}

/// The top-level arguments of a macro call, from just past its `(` to the
/// matching `)`, with line comments dropped.
fn macro_args(body: &str) -> Option<Vec<String>> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                current.push(c);
                while let Some(s) = chars.next() {
                    current.push(s);
                    match s {
                        '\\' => current.extend(chars.next()),
                        '"' => break,
                        _ => {}
                    }
                }
            }
            '/' if chars.peek() == Some(&'/') => {
                for s in chars.by_ref() {
                    if s == '\n' {
                        break;
                    }
                }
            }
            '(' | '[' | '{' => {
                depth += 1;
                current.push(c);
            }
            ')' if depth == 0 => {
                let last = current.trim();
                if !last.is_empty() {
                    args.push(last.to_string());
                }
                return Some(args);
            }
            ')' | ']' | '}' => {
                depth = depth.saturating_sub(1);
                current.push(c);
            }
            ',' if depth == 0 => {
                args.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(c),
        }
    }
    None
}

/// A translation that drops or renames a `{field}` / `%1` shows the raw token,
/// or loses the value, in one language only.
#[test]
fn translations_keep_the_english_placeholders() {
    let english = raw_locale_map("en");
    for locale in BASELINE_LOCALES.iter().filter(|id| **id != "en") {
        let mismatched = raw_locale_map(locale)
            .iter()
            .filter_map(|(key, text)| {
                let expected = placeholders(english.get(key)?);
                let found = placeholders(text);
                (expected != found).then(|| format!("{key}: en {expected:?} vs {locale} {found:?}"))
            })
            .collect::<Vec<_>>();
        assert!(
            mismatched.is_empty(),
            "placeholders differ between en and {locale}:\n{}",
            mismatched.join("\n")
        );
    }
    let with_placeholders = english
        .values()
        .filter(|text| !placeholders(text).is_empty())
        .count();
    assert!(
        with_placeholders >= 20,
        "only {with_placeholders} English texts carry placeholders — the scan is not seeing them"
    );
}

#[test]
fn placeholder_scan_sees_named_and_positional_tokens() {
    let found = placeholders("{count} of %1 in {adapter-name}; {not a token} 100% {}");
    let expected = ["%1", "{adapter-name}", "{count}"]
        .map(str::to_string)
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(found, expected);
}

/// The RU UI spells this word «кэш», never «кеш» — including mid-word
/// («закешировало», «некешированным»). Catches the spelling regressing key
/// by key instead of relying on a one-off sweep.
#[test]
fn russian_locale_never_spells_cache_kesh() {
    let offenders = raw_locale_map("ru")
        .into_iter()
        .filter(|(_, text)| text.to_lowercase().contains("кеш"))
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    assert!(
        offenders.is_empty(),
        "locale 'ru' uses the «кеш» spelling instead of «кэш» in: {}",
        offenders.join(", ")
    );
}

/// One word per concept in each language: leak protection, the additional
/// route and VPN each had two or three spellings side by side. Placeholders
/// and the rules file name are skipped: they name a value or a file, not the
/// concept.
#[test]
fn retired_spellings_stay_out_of_the_locales() {
    const RETIRED: [(&str, &[&str]); 2] = [
        (
            "en",
            &[
                "kill switch",
                "kill-switch",
                "killswitch",
                "leak guard",
                "leak-guard",
                "emergency block",
                "secondary",
            ],
        ),
        (
            "ru",
            &[
                "защита от утечек",
                "защиты от утечек",
                "защите от утечек",
                "защиту от утечек",
                "защитой от утечек",
                "аварийная блокировка",
                "аварийной блокировки",
                "аварийное отключение",
                "впн",
                "запасн",
                "вторичн",
                "резервный маршрут",
                "через резервный",
            ],
        ),
    ];
    for (locale, retired) in RETIRED {
        let offenders = raw_locale_map(locale)
            .into_iter()
            .filter_map(|(key, text)| {
                let text = without_placeholders(&text)
                    .to_lowercase()
                    .replace("rules_secondary.txt", "");
                retired
                    .iter()
                    .find(|spelling| text.contains(**spelling))
                    .map(|spelling| format!("{key} («{spelling}»)"))
            })
            .collect::<Vec<_>>();
        assert!(
            offenders.is_empty(),
            "locale '{locale}' uses a retired spelling in: {}",
            offenders.join(", ")
        );
    }
}

fn without_placeholders(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut depth = 0usize;
    for ch in text.chars() {
        match ch {
            '{' => depth += 1,
            '}' if depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }
    out
}

/// Locales every key must exist in, per the "both locale files" rule.
const BASELINE_LOCALES: [&str; 2] = ["en", "ru"];

/// `{name}` and `%N` tokens of one localized text.
fn placeholders(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let bytes = text.as_bytes();
    for (start, byte) in bytes.iter().enumerate() {
        match byte {
            b'{' => {
                let rest = &text[start + 1..];
                if let Some(end) = rest.find('}') {
                    let name = &rest[..end];
                    if !name.is_empty()
                        && name
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                    {
                        found.insert(format!("{{{name}}}"));
                    }
                }
            }
            b'%' => {
                let digits = text[start + 1..]
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>();
                if !digits.is_empty() {
                    found.insert(format!("%{digits}"));
                }
            }
            _ => {}
        }
    }
    found
}

/// One bundled locale file flattened to dotted keys, with no fallback merged in.
fn raw_locale_map(locale: &str) -> BTreeMap<String, String> {
    fn flatten(node: &Value, prefix: &str, out: &mut BTreeMap<String, String>) {
        let Some(object) = node.as_object() else {
            return;
        };
        for (key, child) in object {
            if prefix.is_empty() && key == "metadata" {
                continue;
            }
            let child_key = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            match child {
                Value::String(text) => {
                    out.insert(child_key, text.clone());
                }
                Value::Object(_) => flatten(child, &child_key, out),
                _ => {}
            }
        }
    }
    // The tray file is part of the language: the window reads both.
    let mut map = BTreeMap::new();
    for file in [format!("{locale}.json"), format!("tray/{locale}.json")] {
        let path = workspace_root().join("locales").join(file);
        let raw = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read '{}': {error}", path.display()));
        let parsed = serde_json::from_str::<Value>(raw.trim_start_matches('\u{feff}'))
            .unwrap_or_else(|error| panic!("failed to parse '{}': {error}", path.display()));
        flatten(&parsed, "", &mut map);
    }
    map
}

/// Files under `dir` with one of `extensions`, as (path, contents), skipping
/// build output.
fn collect_files_with_extension(dir: &Path, extensions: &[&str], out: &mut Vec<(PathBuf, String)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) != Some("target") {
                collect_files_with_extension(&path, extensions, out);
            }
        } else if path
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|ext| extensions.contains(&ext))
        {
            if let Ok(contents) = fs::read_to_string(&path) {
                out.push((path, contents));
            }
        }
    }
}

/// Rust sources of every crate that can log, minus this file, whose fixtures
/// are not call sites.
fn log_sources() -> Vec<String> {
    let mut sources = Vec::new();
    for root in LOG_SOURCE_ROOTS {
        collect_files_with_extension(&workspace_root().join(root), &["rs"], &mut sources);
    }
    sources
        .into_iter()
        .filter(|(path, _)| !path.ends_with("shared/contracts/tests/localization_keys.rs"))
        .map(|(_, contents)| contents)
        .collect()
}

fn is_allowed_runtime_dynamic_key(key: &str) -> bool {
    key.starts_with("action.") && key.ends_with(".description")
}

fn harvest_keys(content: &str, keys: &mut BTreeSet<String>) {
    for literal in extract_quoted_strings(content) {
        if looks_like_locale_key(&literal) {
            keys.insert(literal);
        }
    }
}

/// The files of one walked tree, failing loudly on a tree that moved.
fn runtime_key_tree_files(root: &str, extensions: &[&str]) -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    collect_files_with_extension(&workspace_root().join(root), extensions, &mut files);
    assert!(
        !files.is_empty(),
        "no {extensions:?} files under '{root}' — the walk found nothing to check"
    );
    files
}

fn collect_runtime_locale_keys() -> Vec<String> {
    let mut keys = BTreeSet::new();
    for relative_path in RUNTIME_KEY_SOURCE_FILES {
        let path = workspace_root().join(relative_path);
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read '{}': {error}", path.display()));
        harvest_keys(&content, &mut keys);
    }
    for (root, extensions) in RUNTIME_KEY_TREES {
        for (_, content) in runtime_key_tree_files(root, extensions) {
            harvest_keys(&content, &mut keys);
        }
    }
    keys.into_iter().collect::<Vec<_>>()
}

/// The QML libraries and the TUI screens name keys of their own; a walk that
/// stopped at `.qml` files or at the TUI's central table would pass blind.
#[test]
fn the_key_scan_reads_qml_libraries_and_every_tui_module() {
    fn keys_from(
        root: &str,
        extensions: &[&str],
        pick: impl Fn(&Path) -> bool,
    ) -> BTreeSet<String> {
        let mut keys = BTreeSet::new();
        for (path, content) in runtime_key_tree_files(root, extensions) {
            if pick(&path) {
                harvest_keys(&content, &mut keys);
            }
        }
        keys
    }
    let from_js = keys_from("apps/desktop/qml", &["qml", "js"], |path| {
        path.extension().and_then(|e| e.to_str()) == Some("js")
    });
    assert!(
        !from_js.is_empty(),
        "no keys found in the QML JavaScript libraries"
    );
    let from_tui_screens = keys_from("apps/tui/src", &["rs"], |path| {
        !path.ends_with("apps/tui/src/keys.rs")
    });
    assert!(
        !from_tui_screens.is_empty(),
        "no keys found in TUI modules other than keys.rs"
    );
}

/// A file name such as the TUI's `tui.json` starts with a key family.
#[test]
fn a_file_name_is_not_taken_for_a_key() {
    assert!(!looks_like_locale_key("tui.json"));
    assert!(!looks_like_locale_key("rules.txt"));
    assert!(looks_like_locale_key("tui.settings.title"));
}

/// Is this string SHAPED like a locale key?
///
/// The root is checked against the families the LOCALE FILES actually declare,
/// not against `ALLOWED_TOP_LEVEL_DOMAINS`. Deciding both questions from one
/// hand-typed list made the gate blind in both directions at once: a family
/// missing from it was not recognised as a key in code, so every key under it
/// went unchecked, while the locale file holding it failed the root-family
/// test. Reading the roots from the files means a family someone adds is
/// covered the moment it exists, and `ALLOWED_TOP_LEVEL_DOMAINS` goes back to
/// being one side of a comparison instead of the input to both.
///
/// A dotted lowercase string is also how a file name and a hostname look, so
/// the root check is what keeps `eula.en.md` and `docs.search.example` out.
fn looks_like_locale_key(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    if !locale_root_families().contains(first) {
        return false;
    }

    let tail = parts.collect::<Vec<_>>();
    if tail.is_empty() {
        return false;
    }

    if !is_valid_key_segment(first) {
        return false;
    }

    let names_a_file = tail
        .last()
        .is_some_and(|last| FILE_EXTENSIONS.contains(last));
    !names_a_file && tail.into_iter().all(is_valid_key_segment)
}

/// Extensions of files the code names; no locale key ends in one.
const FILE_EXTENSIONS: [&str; 8] = ["json", "md", "txt", "toml", "log", "ndjson", "qml", "js"];

/// Root families declared by the shipped locale files, unioned with the
/// allowlist so a family that exists only in code is still recognised — and
/// then reported as an unknown key rather than quietly skipped.
fn locale_root_families() -> &'static BTreeSet<String> {
    static ROOTS: std::sync::OnceLock<BTreeSet<String>> = std::sync::OnceLock::new();
    ROOTS.get_or_init(|| {
        let mut roots: BTreeSet<String> = ALLOWED_TOP_LEVEL_DOMAINS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        for locale_file in locale_files() {
            let Ok(raw) = fs::read_to_string(&locale_file) else {
                continue;
            };
            let Ok(parsed) = serde_json::from_str::<Value>(raw.trim_start_matches('\u{feff}'))
            else {
                continue;
            };
            let Some(object) = parsed.as_object() else {
                continue;
            };
            roots.extend(object.keys().filter(|k| *k != "metadata").cloned());
        }
        roots
    })
}

fn is_valid_key_segment(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

fn extract_quoted_strings(content: &str) -> Vec<String> {
    let mut values = Vec::new();
    let bytes = content.as_bytes();
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }

        index += 1;
        let mut current = String::new();
        while index < bytes.len() {
            let byte = bytes[index];
            if byte == b'\\' {
                index += 1;
                if index < bytes.len() {
                    current.push(bytes[index] as char);
                    index += 1;
                }
                continue;
            }
            if byte == b'"' {
                index += 1;
                break;
            }
            current.push(byte as char);
            index += 1;
        }

        if !current.is_empty() {
            values.push(current);
        }
    }

    values
}

fn visit_locale_node(
    node: &Value,
    prefix: &str,
    is_root: bool,
    leaf_keys: &mut HashSet<String>,
    namespace_keys: &mut HashSet<String>,
    errors: &mut Vec<String>,
) {
    let Some(object) = node.as_object() else {
        errors.push(format!(
            "expected object at '{}'",
            if prefix.is_empty() { "<root>" } else { prefix }
        ));
        return;
    };

    if !is_root && !prefix.is_empty() {
        if leaf_keys.contains(prefix) {
            errors.push(format!(
                "namespace/leaf conflict: '{}' used as namespace and value",
                prefix
            ));
        }
        namespace_keys.insert(prefix.to_string());
    }

    for (key, child) in object {
        if is_root && key == "metadata" {
            continue;
        }

        if !is_valid_key_segment(key) {
            errors.push(format!(
                "invalid key segment '{}' at '{}'",
                key,
                if prefix.is_empty() { "<root>" } else { prefix }
            ));
        }

        let child_key = if prefix.is_empty() {
            key.to_string()
        } else {
            format!("{prefix}.{key}")
        };

        if child.is_object() {
            visit_locale_node(child, &child_key, false, leaf_keys, namespace_keys, errors);
            continue;
        }

        if let Some(value) = child.as_str() {
            if value.is_empty() {
                errors.push(format!("empty localized value at '{}'", child_key));
            }
            if namespace_keys.contains(&child_key) {
                errors.push(format!(
                    "namespace/leaf conflict: '{}' used as namespace and value",
                    child_key
                ));
            }
            if !leaf_keys.insert(child_key.clone()) {
                errors.push(format!("duplicate localized key '{}'", child_key));
            }
            continue;
        }

        errors.push(format!(
            "invalid value type for '{}': only string and object are allowed",
            child_key
        ));
    }
}

/// The main locale files and the tray files beside them.
fn locale_files() -> Vec<PathBuf> {
    let main = workspace_root().join("locales");
    let mut files = [main.clone(), main.join("tray")]
        .iter()
        .flat_map(|directory| {
            fs::read_dir(directory).unwrap_or_else(|error| {
                panic!(
                    "failed to read locales directory '{}': {error}",
                    directory.display()
                )
            })
        })
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|error| {
            panic!(
                "failed to resolve workspace root from '{}': {error}",
                manifest_dir.display()
            )
        })
}
