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
//! other file that does is listed below with its exact number of reads, so a
//! new read fails the test and so does a removed one, until the list says so.

use std::collections::BTreeMap;
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

/// Modules that own the active revision: the provider itself, and the
/// coordinator that writes the pointer and publishes the overlay. A module is
/// its file plus everything under the directory of the same name.
const OWNERS: &[&str] = &["production_rules_provider", "activation_coordinator"];

/// Readers that need the stored row as such, not the rules in force.
const STORED_ROW_READERS: &[(&str, usize, &str)] = &[
    (
        "production_policy_manager.rs",
        4,
        "service health names the committed revision (id, hash, activation time); \
         a revision mid-activation has no row to name yet",
    ),
    (
        "production_mutation_executor/activation_drive.rs",
        2,
        "compares a just-activated id with the stored pointer, and counts the \
         caller's own stored divergence for the reset preview",
    ),
    (
        "production_diagnostics/internals.rs",
        2,
        "the diagnostics card reports the committed revision id and the \
         candidate count, which are facts about the stored chain",
    ),
];

/// Rule-content readers that still bypass the provider. This list may only
/// shrink: converting one means deleting its entry.
const KNOWN_GAPS: &[(&str, usize, &str)] = &[
    (
        "production_handlers_misc.rs",
        3,
        "rules.list projects the revision row (id and rules) for the GUI; the \
         provider returns a decoded book without the revision id the response carries",
    ),
    (
        "production_merge_preview.rs",
        2,
        "the merge preview reports storage and decode failures as distinct typed \
         errors, which the provider's Option answer collapses",
    ),
    (
        "production_preset_exporter.rs",
        2,
        "the export decodes for the target app platform, not the compiled one, and \
         tells 'no active revision' from a storage error",
    ),
    (
        "production_mutation_executor.rs",
        2,
        "the risk diff compares a candidate with the caller's OWN stored book on \
         purpose (no baseline read-through) and decodes for the executor's platform",
    ),
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

fn direct_reads_in(line: &str) -> usize {
    let code = line.split("//").next().unwrap_or("");
    let calls: usize = DIRECT_READS
        .iter()
        .map(|needle| code.matches(needle).count())
        .sum();
    let squashed: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    calls + squashed.matches(DIRECT_SQL).count()
}

/// Direct reads per production file outside the owners.
fn direct_readers() -> BTreeMap<String, usize> {
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
        let count: usize = lines.iter().map(|l| direct_reads_in(l)).sum();
        if count > 0 {
            readers.insert(rel, count);
        }
    }
    readers
}

#[test]
fn rules_are_read_through_the_provider() {
    let listed: BTreeMap<&str, (usize, &str)> = STORED_ROW_READERS
        .iter()
        .chain(KNOWN_GAPS)
        .map(|(file, count, reason)| (*file, (*count, *reason)))
        .collect();
    assert_eq!(
        listed.len(),
        STORED_ROW_READERS.len() + KNOWN_GAPS.len(),
        "a file is listed twice"
    );

    let found = direct_readers();
    let mut problems = Vec::new();
    for (file, count) in &found {
        match listed.get(file.as_str()) {
            None => problems.push(format!(
                "src/{file}: {count} direct read(s) of the active revision. Read rules \
                 through `ProductionRulesProvider` (it serves a revision mid-activation); \
                 a reader that needs the stored row itself goes in STORED_ROW_READERS \
                 with its reason"
            )),
            Some((expected, _)) if expected != count => problems.push(format!(
                "src/{file}: {count} direct read(s), the list says {expected}. A new read \
                 goes through the provider; a removed one updates the count (or the entry)"
            )),
            Some(_) => {}
        }
    }
    for file in listed.keys() {
        if !found.contains_key(*file) {
            problems.push(format!(
                "src/{file} no longer reads the active revision directly: drop its entry"
            ));
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
    for (file, count, reason) in STORED_ROW_READERS.iter().chain(KNOWN_GAPS) {
        assert!(*count > 0, "{file}: a zero count is not an entry");
        assert!(!reason.trim().is_empty(), "{file}: no reason given");
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

    let found = direct_readers();
    assert!(
        !found.is_empty(),
        "the scan found no direct reader at all, while the lists name several"
    );
}
