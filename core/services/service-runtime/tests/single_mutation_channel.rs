//! Acceptance test pinning the "single mutation
//! channel" invariant in code, not just in design docs.
//!
//! ## What it pins
//!
//! Only the in-crate [`ProductionMutationExecutor`] — reached from
//! [`MutationSubmitHandler`] via the named-pipe IPC entrypoint — is
//! allowed to call the privileged revision-creating methods on
//! [`ActivationCoordinator`]:
//!
//! - `submit_candidate(...)`
//! - `dry_run_apply(...)`
//! - `activate(...)`
//! - `rollback_to(...)`
//!
//! Any other production source-file that grows a call to one of
//! these methods is rejected by this test. The exhaustive allowlist
//! is intentionally tiny:
//!
//! - `production_mutation_executor.rs` — the legitimate caller. Each
//!   privileged method is only reached through the
//!   `MutationSubmitHandler` IPC path.
//! - `activation_coordinator.rs` — the impl block itself plus the
//!   inline `#[cfg(test)]` unit tests. Internal `self.activate(...)`
//!   recursion (rollback → activate) lives here too.
//!
//! ## Why a grep test, not just `pub(crate)`?
//!
//! Crate-level visibility prevents EXTERNAL crates
//! from calling these methods, but visibility alone doesn't catch a
//! second in-crate call site sneaking in. A grep test fails fast on
//! any new file inside `core/services/service-runtime/src/` that
//! starts calling the privileged methods, even before review.
//!
//! ## What this test does NOT catch
//!
//! - Indirect channels (e.g. someone wires `SourceWatcher`'s output
//!   into the existing executor). Removing `source_watcher.rs`
//!   entirely addresses the most obvious such risk.
//! - Reflection / dynamic dispatch through `Arc<dyn MutationExecutor>`
//!   stays a valid path — see the `MutationSubmitHandler` doc-comment
//!   for why that's the SSOT.

use std::fs;
use std::path::{Path, PathBuf};

/// Privileged methods that may only be called through the single
/// IPC channel. Each entry is the literal method name as it appears
/// at the call site (`.<name>(`).
const PRIVILEGED_METHODS: &[&str] = &[
    "submit_candidate",
    "dry_run_apply",
    "activate",
    "rollback_to",
];

/// Files where ANY number of privileged-method calls are accepted.
/// Names are file basenames (no path) — the test compares basenames
/// for portability across host filesystems.
const ALLOWLIST: &[&str] = &[
    // The legitimate caller: routes preview/execute/rollback through
    // the coordinator on behalf of `MutationSubmitHandler`.
    "production_mutation_executor.rs",
    // The impl crate itself: internal `self.<method>` recursion in
    // `rollback_to → activate`, plus all `#[cfg(test)] mod tests`
    // direct calls.
    "activation_coordinator.rs",
];

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

/// Returns `true` when `line` is a method-call site for `method` —
/// not a function definition, not a doc-comment mention, not a
/// trait-method declaration. Heuristic: must contain `.<method>(`
/// (leading dot for method-receiver chains).
fn is_call_site(line: &str, method: &str) -> bool {
    // Skip doc / line comments to keep the heuristic honest.
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return false;
    }
    let needle = format!(".{method}(");
    line.contains(&needle)
}

#[test]
fn privileged_methods_only_called_from_allowlist() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src_root = manifest_dir.join("src");
    assert!(src_root.is_dir(), "expected src/ to exist at {src_root:?}");

    let mut files = Vec::new();
    collect_rust_files(&src_root, &mut files);
    assert!(!files.is_empty(), "no .rs files found under src/");

    let mut offenders: Vec<String> = Vec::new();
    for path in &files {
        let basename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unknown>");
        if ALLOWLIST.contains(&basename) {
            continue;
        }
        let body = match fs::read_to_string(path) {
            Ok(b) => b,
            Err(e) => panic!("read {path:?}: {e}"),
        };
        for (idx, line) in body.lines().enumerate() {
            for method in PRIVILEGED_METHODS {
                if is_call_site(line, method) {
                    offenders.push(format!(
                        "{}:{}: calls .{}( — only {} may do this",
                        path.display(),
                        idx + 1,
                        method,
                        ALLOWLIST.join(" / "),
                    ));
                }
            }
        }
    }

    if !offenders.is_empty() {
        panic!(
            "Single mutation channel invariant violated:\n  {}\n\n\
             If you need a new mutation entrypoint, add it to \
             `ProductionMutationExecutor` instead. If the new call is \
             a legitimate addition, update the ALLOWLIST in \
             tests/single_mutation_channel.rs and document the rationale \
             in LESSONS_LEARNED.md (single mutation channel section).",
            offenders.join("\n  ")
        );
    }
}

#[test]
fn allowlist_files_actually_exist() {
    // Guard against the allowlist drifting into ghost entries —
    // if `production_mutation_executor.rs` ever gets renamed, this
    // test fails fast so the rename author updates the allowlist
    // together.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src_root = manifest_dir.join("src");
    let mut files = Vec::new();
    collect_rust_files(&src_root, &mut files);
    let basenames: Vec<&str> = files
        .iter()
        .map(|p| p.file_name().and_then(|n| n.to_str()).unwrap_or(""))
        .collect();
    for entry in ALLOWLIST {
        assert!(
            basenames.contains(entry),
            "ALLOWLIST entry {entry:?} does not match any file under \
             {src_root:?}; rename the allowlist entry or update the source"
        );
    }
}

#[test]
fn file_watcher_module_is_gone() {
    // `source_watcher.rs` would have constituted a second mutation
    // channel had it ever been wired up. This test pins its absence
    // so a stray git revert doesn't silently bring it back.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = manifest_dir.join("src").join("source_watcher.rs");
    assert!(
        !path.exists(),
        "source_watcher.rs is back at {path:?} — it MUST stay deleted; \
         see TASKS_RU.md §16.QoL+6 for the rationale"
    );
}
