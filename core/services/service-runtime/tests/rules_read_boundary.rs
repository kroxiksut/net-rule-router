//! Holds "every rules read in the service goes through
//! `production_rules_provider`" (AGENTS.md, service invariants) in code.
//!
//! Between phase 2 of an activation (kernel state installed) and phase 3a
//! (active pointer committed) the stored pointer still names the previous
//! revision. The provider serves the revision being applied in that window
//! (`applying_revision_overlay`); a reader that queries the active revision
//! itself sees the old rules and can undo or misreport what phase 2 installed.
//!
//! The scan looks for the storage primitives that read the active revision
//! (or the coordinator's wrappers around them) in production code under
//! `src/`, test modules excluded. Two module owners may use them freely; every
//! other function that does is listed below by name. A listed function, and
//! any function calling one, may name the stored row but not read its rules:
//! a permission for "which revision is committed" must not carry a new read of
//! rule content through it unnoticed.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Call shapes that read the active revision directly.
const DIRECT_READS: &[&str] = &[
    ".get_active_for(",
    ".get_active()",
    ".active_identity_for(",
    ".get_active_pointer",
    "current_active_for(",
    "current_active()",
];

/// Raw SQL selecting the active row, compared with whitespace removed.
const DIRECT_SQL: &str = "status='active'";

/// Rule content of a stored row: the field, the column, the codec module.
const RULES_CONTENT: &str = "rules_json";

/// Where a line outside every `fn` is booked.
const OUTSIDE_FN: &str = "(outside any fn)";

/// Modules that own the active revision: the provider itself, and the
/// coordinator that writes the pointer and publishes the overlay. A module is
/// its file plus everything under the directory of the same name.
const OWNERS: &[&str] = &["production_rules_provider", "activation_coordinator"];

/// A function that needs the stored row as such, not the rules in force.
struct StoredRowReader {
    file: &'static str,
    function: &'static str,
    reason: &'static str,
    /// Set only where the function also reads the stored row's rules, with why
    /// the stored copy and not the book in force is the right answer.
    reads_rules: Option<&'static str>,
}

const STORED_ROW_READERS: &[StoredRowReader] = &[
    StoredRowReader {
        file: "production_policy_manager.rs",
        function: "active_record_for",
        reason: "service health names the caller's committed revision (id, hash, \
                 activation time); a revision mid-activation has no row to name yet",
        reads_rules: None,
    },
    StoredRowReader {
        file: "production_policy_manager.rs",
        function: "load_active",
        reason: "service health reports whether any revision is committed",
        reads_rules: None,
    },
    StoredRowReader {
        file: "production_policy_manager.rs",
        function: "current_revision",
        reason: "service health names the committed revision (id, hash, activation time)",
        reads_rules: None,
    },
    StoredRowReader {
        file: "production_mutation_executor/activation_drive.rs",
        function: "already_active_noop",
        reason: "compares a just-activated id with the caller's stored pointer",
        reads_rules: None,
    },
    StoredRowReader {
        file: "production_diagnostics/internals.rs",
        function: "read_revision_summary",
        reason: "the diagnostics card reports the committed revision id and the \
                 candidate count, which are facts about the stored chain",
        reads_rules: None,
    },
];

fn src_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn collect_rust_files(root: &Path, acc: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(e) => panic!("read_dir {root:?}: {e}"),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, acc);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            acc.push(path);
        }
    }
}

fn relative(path: &Path) -> String {
    path.strip_prefix(src_root())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn in_module(relative: &str, module: &str) -> bool {
    relative == format!("{module}.rs") || relative.starts_with(&format!("{module}/"))
}

/// The directory a file's child modules live in, relative to `src/`.
fn child_module_dir(relative: &str) -> String {
    match relative.rsplit_once('/') {
        Some((dir, "mod.rs")) => format!("{dir}/"),
        None if relative == "lib.rs" || relative == "mod.rs" => String::new(),
        _ => format!("{}/", relative.trim_end_matches(".rs")),
    }
}

/// `mod name;` / `mod name {` after a `#[cfg(test)]`, as (name, inline).
fn test_module_after(lines: &[&str], attr_line: usize) -> Option<(String, bool)> {
    let item = lines[attr_line + 1..]
        .iter()
        .map(|l| l.trim())
        .find(|l| !l.is_empty() && !l.starts_with("#["))?;
    let rest = ["pub(crate) mod ", "pub(super) mod ", "pub mod ", "mod "]
        .iter()
        .find_map(|prefix| item.strip_prefix(prefix))?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    let tail = rest[name.len()..].trim_start();
    if tail.starts_with(';') {
        Some((name, false))
    } else if tail.starts_with('{') {
        Some((name, true))
    } else {
        None
    }
}

/// Production lines of a file, and the out-of-line test modules it declares.
/// An inline test module ends the production part: in this crate it is always
/// the last item of its file.
fn production_lines(relative: &str, body: &str) -> (Vec<String>, Vec<String>) {
    let lines: Vec<&str> = body.lines().collect();
    let mut kept = Vec::new();
    let mut test_modules = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if line.trim() == "#[cfg(test)]" {
            match test_module_after(&lines, idx) {
                Some((_, true)) => break,
                Some((name, false)) => {
                    test_modules.push(format!("{}{name}", child_module_dir(relative)));
                }
                None => {}
            }
        }
        kept.push((*line).to_string());
    }
    (kept, test_modules)
}

fn code_of(line: &str) -> &str {
    line.split("//").next().unwrap_or("")
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Occurrences of `word` not glued to a longer identifier.
fn word_count(code: &str, word: &str) -> usize {
    code.match_indices(word)
        .filter(|&(at, _)| {
            let before = code[..at].chars().next_back();
            let after = code[at + word.len()..].chars().next();
            !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
        })
        .count()
}

fn direct_reads_in(line: &str) -> usize {
    let code = code_of(line);
    let calls: usize = DIRECT_READS
        .iter()
        .map(|needle| code.matches(needle).count())
        .sum();
    let squashed: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    calls + squashed.matches(DIRECT_SQL).count()
}

fn rules_content_reads_in(line: &str) -> usize {
    word_count(code_of(line), RULES_CONTENT)
}

/// The function a line declares, when it starts an `fn` item.
fn declared_fn(code: &str) -> Option<String> {
    let mut tokens = code.split_whitespace();
    loop {
        let token = tokens.next()?;
        if token == "fn" {
            let name: String = tokens
                .next()?
                .chars()
                .take_while(|c| is_ident(*c))
                .collect();
            return (!name.is_empty()).then_some(name);
        }
        if token.starts_with("pub(") && !token.ends_with(')') {
            // `pub(in path)` spans two tokens.
            tokens.find(|t| t.ends_with(')'))?;
            continue;
        }
        let qualifier = token == "pub"
            || token.starts_with("pub(")
            || matches!(
                token,
                "async" | "const" | "unsafe" | "extern" | "default" | "\"C\""
            );
        if !qualifier {
            return None;
        }
    }
}

#[derive(Default, Debug, PartialEq)]
struct FnReads {
    active: usize,
    rules_content: usize,
    /// Listed readers this function calls as methods.
    calls: BTreeSet<&'static str>,
}

/// Reads per function of one file. A function runs from its declaration to
/// the first line at its indentation or shallower that starts with `}`, or to
/// the next declaration at that depth (rustfmt layout).
fn reads_by_function(lines: &[String]) -> BTreeMap<String, FnReads> {
    let mut open: Vec<(String, usize)> = Vec::new();
    let mut out: BTreeMap<String, FnReads> = BTreeMap::new();
    for line in lines {
        let code = code_of(line);
        let trimmed = code.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        let indent = code.len() - trimmed.len();
        let declares = declared_fn(trimmed);
        if let Some(name) = &declares {
            while open.last().is_some_and(|(_, at)| *at >= indent) {
                open.pop();
            }
            open.push((name.clone(), indent));
        }
        let active = direct_reads_in(code);
        let rules_content = rules_content_reads_in(code);
        let calls: Vec<&'static str> = if declares.is_some() {
            Vec::new()
        } else {
            STORED_ROW_READERS
                .iter()
                .map(|r| r.function)
                .filter(|f| code.contains(&format!(".{f}(")))
                .collect()
        };
        if active > 0 || rules_content > 0 || !calls.is_empty() {
            let owner = open.last().map_or(OUTSIDE_FN, |(name, _)| name.as_str());
            let entry = out.entry(owner.to_string()).or_default();
            entry.active += active;
            entry.rules_content += rules_content;
            entry.calls.extend(calls);
        }
        if trimmed.starts_with('}') {
            while open.last().is_some_and(|(_, at)| *at >= indent) {
                open.pop();
            }
        }
    }
    out
}

/// Reads per (file, function) of production code outside the owners.
fn direct_readers() -> BTreeMap<(String, String), FnReads> {
    let mut files = Vec::new();
    collect_rust_files(&src_root(), &mut files);
    assert!(!files.is_empty(), "no .rs files found under src/");

    let mut production = Vec::new();
    let mut test_modules = Vec::new();
    for path in &files {
        let rel = relative(path);
        let body = match fs::read_to_string(path) {
            Ok(b) => b,
            Err(e) => panic!("read {path:?}: {e}"),
        };
        let (lines, tests) = production_lines(&rel, &body);
        test_modules.extend(tests);
        production.push((rel, lines));
    }

    let mut readers = BTreeMap::new();
    for (rel, lines) in production {
        if OWNERS.iter().any(|m| in_module(&rel, m))
            || test_modules.iter().any(|m| in_module(&rel, m))
        {
            continue;
        }
        for (function, reads) in reads_by_function(&lines) {
            readers.insert((rel.clone(), function), reads);
        }
    }
    readers
}

#[test]
fn rules_are_read_through_the_provider() {
    let listed: BTreeMap<(&str, &str), &StoredRowReader> = STORED_ROW_READERS
        .iter()
        .map(|r| ((r.file, r.function), r))
        .collect();
    assert_eq!(
        listed.len(),
        STORED_ROW_READERS.len(),
        "a function is listed twice"
    );

    let found = direct_readers();
    let mut problems = Vec::new();
    for ((file, function), reads) in &found {
        let entry = listed.get(&(file.as_str(), function.as_str()));
        if reads.active > 0 && entry.is_none() {
            problems.push(format!(
                "src/{file}: `{function}` reads the active revision directly ({} read(s)). \
                 Read rules through `ProductionRulesProvider` (it serves a revision \
                 mid-activation); a function that needs the stored row itself goes in \
                 STORED_ROW_READERS with its reason",
                reads.active
            ));
        }
        let grants_rules = entry.is_some_and(|r| r.reads_rules.is_some());
        if reads.rules_content > 0 && !grants_rules && (entry.is_some() || !reads.calls.is_empty())
        {
            let via = if entry.is_some() {
                "a stored-row reader".to_string()
            } else {
                let callees: Vec<&str> = reads.calls.iter().copied().collect();
                format!("it calls the stored-row reader(s) {}", callees.join(", "))
            };
            problems.push(format!(
                "src/{file}: `{function}` reads stored rule content (`{RULES_CONTENT}`) and \
                 {via}. The rules in force come from `ProductionRulesProvider`; a \
                 permission to name the committed revision does not cover its rules"
            ));
        }
    }
    for reader in STORED_ROW_READERS {
        let key = (reader.file.to_string(), reader.function.to_string());
        match found.get(&key) {
            Some(reads) if reads.active > 0 => {
                if reader.reads_rules.is_some() && reads.rules_content == 0 {
                    problems.push(format!(
                        "src/{}: `{}` no longer reads stored rules: drop its `reads_rules`",
                        reader.file, reader.function
                    ));
                }
            }
            _ => problems.push(format!(
                "src/{}: `{}` no longer reads the active revision directly: drop its entry",
                reader.file, reader.function
            )),
        }
    }
    assert!(
        problems.is_empty(),
        "rules-read boundary:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn every_listed_reader_says_why() {
    for reader in STORED_ROW_READERS {
        let at = format!("{}::{}", reader.file, reader.function);
        assert!(
            !reader.function.trim().is_empty(),
            "{at}: no function named"
        );
        assert!(!reader.reason.trim().is_empty(), "{at}: no reason given");
        if let Some(why) = reader.reads_rules {
            assert!(
                !why.trim().is_empty(),
                "{at}: rule content read without a reason"
            );
        }
    }
}

/// The scanner must see what it is meant to see, or the test above passes on
/// nothing.
#[test]
fn the_scanner_counts_what_it_claims_to() {
    assert_eq!(direct_reads_in("let r = repo.get_active_for(p)?;"), 1);
    assert_eq!(direct_reads_in("repo.get_active().ok()"), 1);
    assert_eq!(
        direct_reads_in("\"SELECT x FROM revisions WHERE status = 'active'\""),
        1
    );
    assert_eq!(direct_reads_in("WHERE status != 'active'"), 0);
    assert_eq!(direct_reads_in("// repo.get_active_for(p)"), 0);
    assert_eq!(direct_reads_in("self.coordinator.current_active()"), 1);

    assert_eq!(rules_content_reads_in("let n = count(&rec.rules_json);"), 1);
    assert_eq!(
        rules_content_reads_in("SELECT revision_id, rules_json FROM"),
        1
    );
    assert_eq!(rules_content_reads_in("c.rules_json_in_force_for(p)"), 0);
    assert_eq!(rules_content_reads_in("// rec.rules_json"), 0);

    assert_eq!(
        declared_fn("pub(super) fn execute<T>(").as_deref(),
        Some("execute")
    );
    assert_eq!(
        declared_fn("pub(in crate::x) async fn go(").as_deref(),
        Some("go")
    );
    assert_eq!(
        declared_fn("fn load_active(&self);").as_deref(),
        Some("load_active")
    );
    assert_eq!(declared_fn("const LIMIT: usize = 4;"), None);
    assert_eq!(declared_fn("let f: fn(u8) = g;"), None);

    let body = "fn a() { repo.get_active_for(p); }\n\
                #[cfg(test)]\n\
                mod helpers;\n\
                #[cfg(test)]\n\
                #[allow(clippy::unwrap_used)]\n\
                mod tests {\n\
                    fn b() { repo.get_active_for(p); }\n\
                }\n";
    let (lines, tests) = production_lines("foo.rs", body);
    assert_eq!(lines.iter().map(|l| direct_reads_in(l)).sum::<usize>(), 1);
    assert_eq!(tests, vec!["foo/helpers".to_string()]);
    assert_eq!(child_module_dir("bar/mod.rs"), "bar/");
    assert_eq!(child_module_dir("lib.rs"), "");

    // Reads land on the function that holds them, a nested fn included, and a
    // caller of a listed reader is seen calling it.
    let file: Vec<String> = [
        "impl X {",
        "    fn current_revision(&self) -> Option<R> {",
        "        let r = self.c.current_active().ok()?;",
        "        fn inner() {",
        "            rec.rules_json;",
        "        }",
        "        Some(r)",
        "    }",
        "",
        "    fn counts(&self) -> usize {",
        "        let rec = self.current_revision()?;",
        "        count(&rec.rules_json)",
        "    }",
        "}",
        "const SQL: &str = \"WHERE status = 'active'\";",
    ]
    .iter()
    .map(|l| (*l).to_string())
    .collect();
    let reads = reads_by_function(&file);
    let at = |f: &str| reads.get(f).map(|r| (r.active, r.rules_content));
    assert_eq!(at("current_revision"), Some((1, 0)));
    assert_eq!(at("inner"), Some((0, 1)));
    assert_eq!(at("counts"), Some((0, 1)));
    assert_eq!(at(OUTSIDE_FN), Some((1, 0)));
    assert!(reads
        .get("counts")
        .is_some_and(|r| r.calls.contains("current_revision")));

    let found = direct_readers();
    assert!(
        found.values().any(|r| r.active > 0),
        "the scan found no direct reader at all, while the list names several"
    );
}
