//! Every error code a client can be handed has words in every baseline locale.
//!
//! The window, the tray and the terminal show a refusal as the text of
//! `errors.<code>`; a code without that key reaches the screen as its bare
//! English slug, in the Russian window too. `CLIENT_ERROR_CODES` is the
//! catalogue. This gate holds the locales to it, and holds to it every
//! producer that spells a code itself — the service, the client library, the
//! launcher, the elevation broker, the terminal — so a new refusal cannot skip
//! both. Producers that already name the catalogue's constants are covered by
//! construction; the service still spells its refusals as literals, which the
//! scan below reads.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use nrr_shared::client_error_codes::CLIENT_ERROR_CODES;
use nrr_shared::ipc_transport::IpcErrorCode;
use serde_json::Value;

const BASELINE_LOCALES: [&str; 2] = ["en", "ru"];

/// Source trees whose code builds the error codes clients receive.
const PRODUCER_ROOTS: &[&str] = &[
    "core/services/service-runtime/src",
    "core/ipc-client/src",
    "core/client-logic/src",
    "apps/desktop/launcher/src",
    "apps/desktop/broker/src",
    "apps/tui/src",
];

/// Call sites whose first argument (or field value) is the code: a `code`
/// field, the refusal constructors, the audit-chain `failed` closure.
const CODE_SITES: &[&str] = &[
    "code:",
    "Refusal::new(",
    "BrokerResponse::err(",
    "Failure::code(",
    "failed(",
];

/// Takes the code as its SECOND argument, after the correlation id.
const SECOND_ARGUMENT_CODE_SITE: &str = "LauncherRpcResponse::err(";

/// Functions that map a failure to its code in a `match`, where the literal
/// sits in a tuple or an arm rather than at a call site. Every slug-shaped
/// literal in their bodies is a code.
const CODE_MAPPERS: &[(&str, &str)] = &[
    (
        "core/services/service-runtime/src/production_mutation_executor.rs",
        "policy_error",
    ),
    (
        "core/services/service-runtime/src/production_mutation_executor.rs",
        "rejection_to_operation_error",
    ),
    ("core/ipc-client/src/wire_error.rs", "ipc_error_to_wire"),
    ("apps/desktop/broker/src/server.rs", "failure_code"),
    ("apps/desktop/launcher/src/local_handlers.rs", "wire_code"),
    ("apps/desktop/launcher/src/preset_handlers.rs", "wire_code"),
    (
        "apps/desktop/launcher/src/user_settings_bridge.rs",
        "wire_code",
    ),
];

/// Codes a producer spells that no client shows as `errors.<code>` text.
const NOT_SHOWN: &[(&str, &str)] = &[
    (
        "unavailable",
        "An auto-rule author refusal: the client receives `precondition-failed`, \
         and this code only opens the message.",
    ),
    ("authoring-unavailable", "Same as `unavailable`."),
    (
        "update-check-failed",
        "The update check words its failure with its own status line, \
         `status.update-check-failed`.",
    ),
];

#[test]
fn every_client_error_code_has_words_in_every_baseline_locale() {
    let english = locale_map("en");
    let mut missing = Vec::new();
    for locale in BASELINE_LOCALES {
        let map = locale_map(locale);
        for code in CLIENT_ERROR_CODES {
            let key = format!("errors.{code}");
            match map.get(&key) {
                None => missing.push(format!("{locale}: {key} is missing")),
                Some(text) if text.trim().is_empty() => {
                    missing.push(format!("{locale}: {key} is empty"));
                }
                Some(text) if locale != "en" && english.get(&key) == Some(text) => {
                    missing.push(format!("{locale}: {key} is the English text"));
                }
                Some(_) => {}
            }
        }
    }
    assert!(
        missing.is_empty(),
        "client error codes without words (add the key to every baseline locale):\n  {}",
        missing.join("\n  ")
    );
}

#[test]
fn the_catalogue_holds_each_code_once_as_a_slug() {
    let mut seen = BTreeSet::new();
    for code in CLIENT_ERROR_CODES {
        assert!(is_slug(code), "`{code}` is not a kebab-case slug");
        assert!(seen.insert(*code), "`{code}` is catalogued twice");
    }
}

#[test]
fn every_envelope_code_is_catalogued() {
    let source = read_repo_file("shared/contracts/src/ipc_transport.rs");
    let variants = enum_variants(&mask(&source).text, "IpcErrorCode");
    assert!(
        !variants.is_empty(),
        "IpcErrorCode not found — the scan is broken"
    );
    assert_eq!(
        variants.len(),
        IpcErrorCode::ALL.len(),
        "IpcErrorCode::ALL must list every variant: {variants:?}"
    );
    for variant in &variants {
        let wire = Value::String(snake_case(variant));
        let code: IpcErrorCode = serde_json::from_value(wire)
            .unwrap_or_else(|e| panic!("variant {variant} does not decode: {e}"));
        assert!(
            IpcErrorCode::ALL.contains(&code),
            "{variant} is missing from IpcErrorCode::ALL"
        );
    }
    for code in IpcErrorCode::ALL {
        assert!(
            CLIENT_ERROR_CODES.contains(&code.client_slug()),
            "{code:?} reaches clients as `{}`, which is not catalogued",
            code.client_slug()
        );
    }
}

#[test]
fn every_named_code_constant_is_catalogued() {
    let masked = mask(&read_repo_file(
        "shared/contracts/src/client_error_codes.rs",
    ));
    let constants = const_literals(&masked, "pub const ");
    assert!(
        !constants.is_empty(),
        "no constants found — the scan is broken"
    );
    for (name, value) in constants {
        assert!(
            CLIENT_ERROR_CODES.contains(&value.as_str()),
            "{name} = `{value}` is not in CLIENT_ERROR_CODES"
        );
    }
}

#[test]
fn every_code_a_producer_spells_is_catalogued() {
    let mut found: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for root in PRODUCER_ROOTS {
        let mut files = Vec::new();
        collect_production_sources(&workspace_root().join(root), &mut files);
        assert!(
            !files.is_empty(),
            "no sources under {root} — the walk is broken"
        );
        for file in files {
            let source = std::fs::read_to_string(&file)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", file.display()));
            for code in codes_at_call_sites(&source) {
                found.entry(code).or_default().insert(relative(&file));
            }
        }
    }
    for (file, function) in CODE_MAPPERS {
        let masked = mask(&read_repo_file(file));
        let codes = codes_in_function(&masked, function)
            .unwrap_or_else(|| panic!("fn {function} not found in {file} — update CODE_MAPPERS"));
        for code in codes {
            found.entry(code).or_default().insert((*file).to_owned());
        }
    }

    let not_shown: BTreeMap<&str, &str> = NOT_SHOWN.iter().copied().collect();
    let uncatalogued: Vec<String> = found
        .iter()
        .filter(|(code, _)| {
            !CLIENT_ERROR_CODES.contains(&code.as_str()) && !not_shown.contains_key(code.as_str())
        })
        .map(|(code, files)| {
            let files: Vec<&str> = files.iter().map(String::as_str).collect();
            format!("`{code}` in {}", files.join(", "))
        })
        .collect();
    assert!(
        uncatalogued.is_empty(),
        "error codes a client can receive but CLIENT_ERROR_CODES does not list \
         (catalogue them and add `errors.<code>` to every locale, or list them in \
         NOT_SHOWN with the reason no client shows them):\n  {}",
        uncatalogued.join("\n  ")
    );
    for (code, _) in NOT_SHOWN {
        assert!(
            found.contains_key(*code),
            "NOT_SHOWN lists `{code}`, which no producer spells any more — remove it"
        );
        assert!(
            !CLIENT_ERROR_CODES.contains(code),
            "`{code}` is both catalogued and listed as never shown"
        );
    }
}

#[test]
fn the_window_and_the_terminal_look_codes_up_under_errors() {
    let pure = read_repo_file("apps/desktop/qml/lib/pure.js");
    assert!(
        pure.contains("var key = \"errors.\" + slug"),
        "pure.js ipcErrorLabel no longer reads `errors.<code>` — this gate checks the wrong keys"
    );
    let terminal = read_repo_file("apps/tui/src/screens/rules/apply.rs");
    assert!(
        terminal.contains("format!(\"errors.{slug}\")"),
        "the terminal no longer reads `errors.<code>` — this gate checks the wrong keys"
    );
}

#[test]
fn the_producer_scan_reads_call_sites_and_skips_tests_comments_and_strings() {
    let source = r##"
        // code: "in-a-comment"
        /* Refusal::new("in-a-block-comment") */
        fn produce() -> Result<(), Refusal> {
            Err(Refusal::new(
                "spread-over-lines",
                format!("{x}"),
            ))
        }
        const BUSY_CODE: &str = "from-a-const";
        const OTHER_CODE: &'static str = "from-a-static-const";
        fn field() {
            let e = OperationError { reason_code: "not-a-code", code: "from-a-field".into() };
            let s = "code: \"inside-a-string\"";
            let brace = '{';
            let quote = '"';
            LauncherRpcResponse::err(id.clone(), "second-argument", m);
        }
        #[cfg(test)]
        mod tests {
            fn t() { failed("only-in-tests", m) }
        }
        fn after() { failed("after-the-tests", m) }
    "##;
    let found = codes_at_call_sites(source);
    let expected: BTreeSet<String> = [
        "after-the-tests",
        "from-a-const",
        "from-a-field",
        "from-a-static-const",
        "second-argument",
        "spread-over-lines",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(found, expected);
}

#[test]
fn the_mapper_scan_reads_tuple_and_arm_literals() {
    let source = r#"
        fn other() -> &'static str { "not-this-one" }
        fn map(e: &E) -> (&'static str, String) {
            match e {
                E::A => ("tuple-code", "prose with spaces".into()),
                E::B => {
                    ("arm-code", format!("{e}"))
                }
                E::C => (KNOWN, String::new()),
            }
        }
    "#;
    let codes = codes_in_function(&mask(source), "map").unwrap_or_default();
    let expected: BTreeSet<String> = ["arm-code", "tuple-code"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(codes, expected);
    assert!(codes_in_function(&mask(source), "absent").is_none());
}

// ── Source scanning ──────────────────────────────────────────────────────────

/// Source with comments dropped and every string literal replaced by `"#<n>"`,
/// `n` indexing `literals`: a pattern search cannot hit inside a string, and a
/// brace in a string or a char cannot unbalance a block.
struct Masked {
    text: String,
    literals: Vec<String>,
}

fn mask(source: &str) -> Masked {
    let chars: Vec<char> = source.chars().collect();
    let mut text = String::with_capacity(source.len());
    let mut literals: Vec<String> = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && next == Some('*') {
            let mut depth = 0usize;
            while i < chars.len() {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth = depth.saturating_sub(1);
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            text.push(' ');
            continue;
        }
        if opens_raw_string(&chars, i) {
            let mut j = i + 1;
            let mut hashes = 0;
            while chars.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if chars.get(j) == Some(&'"') {
                let closes = |at: usize| {
                    chars[at] == '"' && (0..hashes).all(|k| chars.get(at + 1 + k) == Some(&'#'))
                };
                let start = j + 1;
                let mut end = start;
                while end < chars.len() && !closes(end) {
                    end += 1;
                }
                literals.push(chars[start..end.min(chars.len())].iter().collect());
                text.push_str(&format!("\"#{}\"", literals.len() - 1));
                i = end + 1 + hashes;
                continue;
            }
        }
        if c == '"' {
            let mut j = i + 1;
            let mut value = String::new();
            while j < chars.len() && chars[j] != '"' {
                if chars[j] == '\\' {
                    value.push('\\');
                    if let Some(&escaped) = chars.get(j + 1) {
                        value.push(escaped);
                    }
                    j += 2;
                    continue;
                }
                value.push(chars[j]);
                j += 1;
            }
            literals.push(value);
            text.push_str(&format!("\"#{}\"", literals.len() - 1));
            i = j + 1;
            continue;
        }
        if c == '\'' {
            if next == Some('\\') {
                let mut j = i + 3;
                while j < chars.len() && chars[j] != '\'' {
                    j += 1;
                }
                text.push(' ');
                i = j + 1;
                continue;
            }
            if chars.get(i + 2) == Some(&'\'') {
                text.push(' ');
                i += 3;
                continue;
            }
        }
        text.push(c);
        i += 1;
    }
    Masked { text, literals }
}

/// Whether `chars[i]` opens a raw string (`r"`, `r#"`, `br"`) rather than
/// ending an identifier.
fn opens_raw_string(chars: &[char], i: usize) -> bool {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    let free = |at: usize| at == 0 || !is_ident(chars[at - 1]);
    chars[i] == 'r'
        && matches!(chars.get(i + 1), Some(&'"') | Some(&'#'))
        && (free(i) || (chars[i - 1] == 'b' && free(i - 1)))
}

/// The text with every `#[cfg(test)]` item removed.
fn without_test_items(text: &str) -> String {
    const MARK: &str = "#[cfg(test)]";
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    while let Some(offset) = text[cursor..].find(MARK) {
        let start = cursor + offset;
        out.push_str(&text[cursor..start]);
        let mut i = start + MARK.len();
        let mut depth = 0usize;
        let mut end = text.len();
        while i < bytes.len() {
            match bytes[i] {
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth = depth.saturating_sub(1),
                b';' if depth == 0 => {
                    end = i + 1;
                    break;
                }
                b'{' if depth == 0 => {
                    end = block_end(bytes, i);
                    break;
                }
                _ => {}
            }
            i += 1;
        }
        cursor = end;
    }
    out.push_str(&text[cursor.min(text.len())..]);
    out
}

/// The index just past the `}` matching the `{` at `open`.
fn block_end(bytes: &[u8], open: usize) -> usize {
    let mut depth = 0usize;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    bytes.len()
}

/// The literal whose placeholder starts at `at`, after optional whitespace.
fn literal_at<'a>(masked: &'a Masked, text: &str, at: usize) -> Option<&'a str> {
    let rest = text.get(at..)?.trim_start();
    let digits = rest.strip_prefix("\"#")?;
    let end = digits.find('"')?;
    let index: usize = digits[..end].parse().ok()?;
    masked.literals.get(index).map(String::as_str)
}

fn preceded_by_ident(text: &str, at: usize) -> bool {
    text[..at]
        .chars()
        .next_back()
        .is_some_and(|c| c.is_alphanumeric() || c == '_')
}

/// Every code literal at a known call site of production code in `source`.
fn codes_at_call_sites(source: &str) -> BTreeSet<String> {
    let masked = mask(source);
    let text = without_test_items(&masked.text);
    let mut codes = BTreeSet::new();
    for site in CODE_SITES {
        for (at, _) in text.match_indices(site) {
            if preceded_by_ident(&text, at) {
                continue;
            }
            if let Some(code) = literal_at(&masked, &text, at + site.len()) {
                codes.insert(code.to_owned());
            }
        }
    }
    for (at, _) in text.match_indices(SECOND_ARGUMENT_CODE_SITE) {
        let bytes = text.as_bytes();
        let mut depth = 0usize;
        let mut i = at + SECOND_ARGUMENT_CODE_SITE.len();
        while i < bytes.len() {
            match bytes[i] {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' if depth == 0 => break,
                b')' | b']' | b'}' => depth -= 1,
                b',' if depth == 0 => {
                    if let Some(code) = literal_at(&masked, &text, i + 1) {
                        codes.insert(code.to_owned());
                    }
                    break;
                }
                _ => {}
            }
            i += 1;
        }
    }
    for (_, value) in const_literals(
        &Masked {
            text,
            literals: masked.literals,
        },
        "const ",
    ) {
        codes.insert(value);
    }
    codes
}

/// `(name, value)` of every `<prefix>NAME: &str = "value"` whose name ends in
/// `_CODE`, or of every such constant when `prefix` is `pub const `.
fn const_literals(masked: &Masked, prefix: &str) -> Vec<(String, String)> {
    let text = &masked.text;
    let mut out = Vec::new();
    for (at, _) in text.match_indices(prefix) {
        if preceded_by_ident(text, at) {
            continue;
        }
        let rest = &text[at + prefix.len()..];
        let Some(colon) = rest.find(':') else {
            continue;
        };
        let name = rest[..colon].trim();
        if !is_const_name(name) {
            continue;
        }
        if prefix == "const " && !name.ends_with("_CODE") {
            continue;
        }
        let Some(eq) = rest[colon..].find('=') else {
            continue;
        };
        let ty = rest[colon + 1..colon + eq].trim();
        if ty != "&str" && ty != "&'static str" {
            continue;
        }
        let value_at = at + prefix.len() + colon + eq + 1;
        if let Some(value) = literal_at(masked, text, value_at) {
            out.push((name.to_owned(), value.to_owned()));
        }
    }
    out
}

fn is_const_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// The slug-shaped literals in the body of `fn <name>`, `None` without one.
fn codes_in_function(masked: &Masked, name: &str) -> Option<BTreeSet<String>> {
    let text = &masked.text;
    let header = format!("fn {name}(");
    let at = text
        .match_indices(&header)
        .map(|(at, _)| at)
        .find(|&at| !preceded_by_ident(text, at))?;
    let open = at + text[at..].find('{')?;
    let body = &text[open..block_end(text.as_bytes(), open)];
    let mut codes = BTreeSet::new();
    for (offset, _) in body.match_indices("\"#") {
        if let Some(value) = literal_at(masked, body, offset) {
            if is_slug(value) {
                codes.insert(value.to_owned());
            }
        }
    }
    Some(codes)
}

/// Variant names of `pub enum <name>`, attributes skipped.
fn enum_variants(text: &str, name: &str) -> Vec<String> {
    let header = format!("pub enum {name} {{");
    let Some(at) = text.find(&header) else {
        return Vec::new();
    };
    let open = at + header.len() - 1;
    let body = &text[open + 1..block_end(text.as_bytes(), open) - 1];
    let mut cleaned = String::new();
    let mut depth = 0usize;
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '#' && chars.peek() == Some(&'[') {
            depth += 1;
            continue;
        }
        if depth > 0 {
            match c {
                '[' => {}
                ']' => depth -= 1,
                _ => {}
            }
            continue;
        }
        cleaned.push(c);
    }
    cleaned
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect()
}

fn snake_case(camel: &str) -> String {
    let mut out = String::new();
    for (i, c) in camel.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn is_slug(value: &str) -> bool {
    !value.is_empty()
        && value.starts_with(|c: char| c.is_ascii_lowercase())
        && !value.ends_with('-')
        && !value.contains("--")
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Production `.rs` files under `dir`: test trees and test-only files skipped.
fn collect_production_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if name != "tests" {
                collect_production_sources(&path, out);
            }
        } else if name.ends_with(".rs")
            && name != "tests.rs"
            && !name.ends_with("_tests.rs")
            && !name.ends_with("_test.rs")
            && !name.starts_with("test_")
        {
            out.push(path);
        }
    }
}

// ── Files ────────────────────────────────────────────────────────────────────

/// Flattened `key → text` of one locale; nested objects join with `.`.
fn locale_map(locale: &str) -> BTreeMap<String, String> {
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
    let raw = read_repo_file(&format!("locales/{locale}.json"));
    let parsed: Value = serde_json::from_str(raw.trim_start_matches('\u{feff}'))
        .unwrap_or_else(|e| panic!("locales/{locale}.json does not parse: {e}"));
    let mut out = BTreeMap::new();
    flatten(&parsed, "", &mut out);
    out
}

fn read_repo_file(relative: &str) -> String {
    let path = workspace_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn relative(path: &Path) -> String {
    path.strip_prefix(workspace_root())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|e| {
            panic!(
                "cannot resolve the workspace root from {}: {e}",
                manifest_dir.display()
            )
        })
}
