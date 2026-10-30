#![allow(clippy::expect_used, clippy::unwrap_used)]

//! The tray is handed a catalogue of its own: its tray files plus the window
//! words `WINDOW_WORDS` names. A key the tray QML asks for that is in neither
//! would show its raw fallback, so every key the tray's files, the components
//! they load and the library functions they call can ask for must resolve.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn qml_root() -> PathBuf {
    repo().join("apps/desktop/qml")
}

/// The shipped files only, never the developer's own overrides.
fn catalogues() -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let user = std::env::temp_dir().join(format!("nrr-tray-words-{}", std::process::id()));
    fs::create_dir_all(&user).expect("empty user locales folder");
    std::env::set_var("NRR_BUNDLED_LOCALES_DIR", repo().join("locales"));
    std::env::set_var("NRR_USER_LOCALES_DIR", &user);
    let window = nrr_shared::load_locale_state()
        .catalog
        .remove("en")
        .expect("English");
    let tray = nrr_desktop_tray::tray_locale_catalog("en")
        .remove("en")
        .expect("English for the tray");
    (window, tray)
}

/// QML types the tray instantiates, from `Tray.qml` through every component
/// it names, by file name.
fn tray_closure() -> Vec<PathBuf> {
    let mut files = BTreeMap::new();
    for dir in ["", "components", "flows", "theme"] {
        for entry in fs::read_dir(qml_root().join(dir)).expect("qml folder") {
            let path = entry.expect("entry").path();
            if path.extension().is_some_and(|e| e == "qml") {
                let name = path.file_stem().unwrap().to_string_lossy().into_owned();
                files.entry(name).or_insert(path);
            }
        }
    }
    let mut seen = BTreeSet::new();
    let mut stack = vec!["Tray".to_string()];
    while let Some(name) = stack.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        let source = fs::read_to_string(&files[&name]).expect("qml");
        stack.extend(
            type_uses(&source)
                .into_iter()
                .filter(|used| files.contains_key(used)),
        );
    }
    seen.iter().map(|name| files[name].clone()).collect()
}

/// Every `Name {` in a QML file.
fn type_uses(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    for (at, _) in source.match_indices('{') {
        let mut end = at;
        while end > 0 && bytes[end - 1] == b' ' {
            end -= 1;
        }
        let mut start = end;
        while start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
            start -= 1;
        }
        if start < end && bytes[start].is_ascii_uppercase() {
            out.push(source[start..end].to_string());
        }
    }
    out
}

/// Quoted literals with whether a `+` follows them.
fn literals(source: &str) -> Vec<(String, bool)> {
    let chars: Vec<char> = source.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let quote = chars[i];
        if quote == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if quote != '"' && quote != '\'' {
            i += 1;
            continue;
        }
        let mut text = String::new();
        let mut j = i + 1;
        while j < chars.len() && chars[j] != quote && chars[j] != '\n' {
            if chars[j] == '\\' {
                j += 1;
            }
            if let Some(&c) = chars.get(j) {
                text.push(c);
            }
            j += 1;
        }
        let mut k = j + 1;
        while chars.get(k).is_some_and(|c| c.is_whitespace()) {
            k += 1;
        }
        out.push((text, chars.get(k) == Some(&'+')));
        i = j + 1;
    }
    out
}

/// The bodies of `function name(` in a JavaScript library, by name.
fn functions(source: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (at, _) in source.match_indices("\nfunction ") {
        let head = &source[at + "\nfunction ".len()..];
        let Some(paren) = head.find('(') else {
            continue;
        };
        let name = head[..paren].trim().to_string();
        let Some(open) = head.find('{') else { continue };
        let mut depth = 0usize;
        let mut end = head.len();
        let mut quote: Option<char> = None;
        let mut escaped = false;
        for (index, c) in head[open..].char_indices() {
            if let Some(q) = quote {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == q || c == '\n' {
                    quote = None;
                }
                continue;
            }
            match c {
                '"' | '\'' | '`' => quote = Some(c),
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + index + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        out.insert(name, head[..end].to_string());
    }
    out
}

/// `Lib.name(` calls in a source, for the libraries the tray imports.
fn library_calls(source: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for lib in ["Pure", "Rules", "Plurals"] {
        let needle = format!("{lib}.");
        for (at, _) in source.match_indices(&needle) {
            let rest = &source[at + needle.len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if rest[name.len()..].trim_start().starts_with('(') {
                out.push((lib.to_string(), name));
            }
        }
    }
    out
}

/// What the tray's sources can ask for: whole keys, and the stems of keys
/// they finish at run time (`"rules.type." + slug`).
fn asked_for(roots: &BTreeSet<String>) -> (BTreeSet<String>, BTreeSet<String>) {
    let libraries: BTreeMap<String, BTreeMap<String, String>> = [
        ("Pure", "pure.js"),
        ("Rules", "rules.js"),
        ("Plurals", "plurals.js"),
    ]
    .into_iter()
    .map(|(lib, file)| {
        let source = fs::read_to_string(qml_root().join("lib").join(file)).expect("library");
        (lib.to_string(), functions(&source))
    })
    .collect();

    let mut sources = Vec::new();
    let mut pending = Vec::new();
    for path in tray_closure() {
        let source = fs::read_to_string(&path).expect("qml");
        pending.extend(library_calls(&source));
        sources.push(source);
    }
    let mut walked = BTreeSet::new();
    while let Some((lib, name)) = pending.pop() {
        let Some(body) = libraries[&lib].get(&name) else {
            continue;
        };
        if !walked.insert((lib.clone(), name)) {
            continue;
        }
        for other in libraries[&lib].keys() {
            if body.contains(&format!("{other}(")) {
                pending.push((lib.clone(), other.clone()));
            }
        }
        pending.extend(library_calls(body));
        sources.push(body.clone());
    }

    let key_shaped = |text: &str| {
        text.split('.').count() > 1
            && roots.contains(text.split('.').next().unwrap_or_default())
            && text
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
    };
    let mut keys = BTreeSet::new();
    let mut stems = BTreeSet::new();
    for source in &sources {
        for (text, continued) in literals(source) {
            if !key_shaped(&text) {
                continue;
            }
            if continued || text.ends_with('.') || text.ends_with('-') {
                stems.insert(text);
            } else {
                keys.insert(text);
            }
        }
    }
    (keys, stems)
}

#[test]
fn every_word_the_tray_asks_for_is_in_its_catalogue() {
    let (window, tray) = catalogues();
    let roots: BTreeSet<String> = window
        .keys()
        .map(|key| key.split('.').next().unwrap_or_default().to_string())
        .collect();
    let (keys, stems) = asked_for(&roots);
    assert!(keys.len() > 200, "the scan found only {} keys", keys.len());

    let mut missing: Vec<String> = keys
        .iter()
        .filter(|key| window.contains_key(*key) && !tray.contains_key(*key))
        .cloned()
        .collect();
    for stem in &stems {
        missing.extend(
            window
                .keys()
                .filter(|key| key.starts_with(stem.as_str()) && !tray.contains_key(*key))
                .map(|key| format!("{key} (from \"{stem}\" + ...)")),
        );
    }
    assert!(
        missing.is_empty(),
        "{} tray words are in neither its tray file nor WINDOW_WORDS:\n{}",
        missing.len(),
        missing.join("\n")
    );
}

/// A word lives in one file: in both, the two texts drift apart.
#[test]
fn no_word_is_in_both_a_main_and_a_tray_file() {
    for language in ["en", "ru"] {
        let flat = |path: PathBuf| {
            let raw = fs::read_to_string(&path).expect("locale file");
            let value: serde_json::Value = serde_json::from_str(&raw).expect("JSON");
            let mut out = BTreeSet::new();
            flatten(&value, "", &mut out);
            out
        };
        let main = flat(repo().join(format!("locales/{language}.json")));
        let tray = flat(repo().join(format!("locales/tray/{language}.json")));
        let both: Vec<&String> = main.intersection(&tray).collect();
        assert!(both.is_empty(), "{language}: {both:?}");
    }
}

/// Both shipped languages carry every tray word; Russian adds only the plural
/// forms English has no use for.
#[test]
fn both_tray_files_hold_the_same_words() {
    let keys = |language: &str| {
        let path = repo().join(format!("locales/tray/{language}.json"));
        let value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("tray file")).expect("JSON");
        let mut out = BTreeSet::new();
        flatten(&value, "", &mut out);
        out
    };
    let (en, ru) = (keys("en"), keys("ru"));
    let lacking: Vec<&String> = en.difference(&ru).collect();
    assert!(lacking.is_empty(), "ru lacks {lacking:?}");
    let extra: Vec<&String> = ru
        .difference(&en)
        .filter(|key| {
            let (stem, form) = key.rsplit_once('.').unwrap_or_default();
            !(["few", "many"].contains(&form) && en.contains(&format!("{stem}.other")))
        })
        .collect();
    assert!(extra.is_empty(), "ru has words English lacks: {extra:?}");
}

fn flatten(node: &serde_json::Value, prefix: &str, out: &mut BTreeSet<String>) {
    let Some(map) = node.as_object() else { return };
    for (key, child) in map {
        if prefix.is_empty() && key == "metadata" {
            continue;
        }
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        if child.is_string() {
            out.insert(path);
        } else {
            flatten(child, &path, out);
        }
    }
}

#[test]
fn the_scan_follows_components_libraries_and_stems() {
    let closure = tray_closure();
    assert!(closure.iter().any(|p| p.ends_with("TrayRuleWindow.qml")));
    assert!(closure.iter().any(|p| p.ends_with("RuleEditDialog.qml")));
    let src = "x = tr(\"rules.type.\" + slug, slug) + tr('tray.menu.title', \"t\") // \"a.b\"";
    assert_eq!(
        literals(src),
        vec![
            ("rules.type.".to_string(), true),
            ("tray.menu.title".to_string(), false),
            ("t".to_string(), false),
        ]
    );
    let body = functions("\nfunction a(x) {\n  if (x) { return \"}\" }\n  return b()\n}\nfunction b() { return 1 }\n");
    assert_eq!(body.len(), 2);
    assert!(body["a"].ends_with("return b()\n}"));
}
