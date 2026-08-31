#![allow(clippy::expect_used)]

//! Guardrail for a trap that only a comment used to hold shut.
//!
//! `run_legacy_preferences_migration` clears the eight preference fields that
//! are the GUI's ONLY live store of adapter bindings. Nothing seeds them back
//! from the service snapshot yet, so calling it blanks the interfaces screen
//! while the service keeps enforcing bindings the user can no longer see or
//! overwrite.
//!
//! The module's own doc comment used to *instruct* the next developer to wire
//! it in. That comment now says the opposite — and this test is why the reversal
//! is worth something: a rule nothing enforces is a rule that gets followed
//! anyway. Delete this test in the same change that adds the reverse seed, not
//! before.

use std::path::Path;

/// Launcher sources that must not call the migration. The module that defines
/// it (and its own tests) obviously may; `lib.rs` re-exports it, which is fine
/// — a re-export is not a call.
fn production_sources() -> Vec<std::path::PathBuf> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    std::fs::read_dir(&src)
        .expect("launcher src/ must be readable")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("rs"))
        .filter(|p| p.file_name().and_then(|n| n.to_str()) != Some("legacy_prefs_migration.rs"))
        .collect()
}

#[test]
fn the_legacy_prefs_migration_has_no_production_caller() {
    let mut callers = Vec::new();
    for path in production_sources() {
        let text = std::fs::read_to_string(&path).expect("read source");
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            // A call is the name followed by `(`. A re-export lists the name
            // inside a `use { … }` block, where it is followed by a comma or a
            // brace — so this tells the two apart without parsing Rust.
            if code.contains("run_legacy_preferences_migration(") {
                callers.push(format!("{}:{}", path.display(), n + 1));
            }
        }
    }
    assert!(
        callers.is_empty(),
        "the legacy preferences migration must not be called until the GUI can \
         seed adapter bindings back from `SnapshotInitial.routePolicy`; calling \
         it today empties the interfaces screen while the service keeps \
         enforcing. Call sites: {callers:?}",
    );
}

#[test]
fn the_scanner_would_notice_a_call() {
    // Positive control: the guard above is a string scan, and a string scan that
    // silently matches nothing is indistinguishable from no guard at all.
    let sources = production_sources();
    assert!(!sources.is_empty(), "no launcher sources were scanned");
    assert!(
        sources
            .iter()
            .any(|p| p.file_name().and_then(|n| n.to_str()) == Some("lib.rs")),
        "lib.rs must be among the scanned files — it is where a caller would go",
    );
    let lib = sources
        .iter()
        .find(|p| p.file_name().and_then(|n| n.to_str()) == Some("lib.rs"))
        .expect("lib.rs");
    let text = std::fs::read_to_string(lib).expect("read lib.rs");
    assert!(
        text.contains("run_legacy_preferences_migration"),
        "the name the scanner looks for must still exist in the crate; if it was \
         renamed, this guardrail is watching a name nobody uses",
    );
}
