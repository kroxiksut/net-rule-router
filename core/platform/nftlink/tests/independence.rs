//! The boundary that makes this crate separable, enforced rather than intended.
//!
//! `nftlink` is meant to leave this repository as its own published project.
//! That is only cheap while it has no dependency on the product around it — one
//! `nrr-*` type reached for "just this once" turns the split from a directory
//! move into a rewrite. Discipline does not hold a boundary for months; a
//! failing build does.

use std::path::Path;

/// Read our own manifest and refuse any product dependency.
///
/// Deliberately textual rather than a `cargo metadata` walk: the rule is about
/// what someone can WRITE in the manifest, and this catches it in the same edit
/// that introduces it, with no tooling to install.
#[test]
fn the_manifest_declares_no_dependency_on_the_product() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest).expect("the crate manifest must be readable");

    for (number, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        assert!(
            !trimmed.starts_with("nrr-") && !trimmed.contains("path = \"../../.."),
            "nftlink must not depend on the product it currently lives in \
             (Cargo.toml line {}: `{trimmed}`). If this crate needs something \
             from the application, the dependency goes the other way — or it is \
             time to split the crate out. See CONTRIBUTING.md.",
            number + 1,
        );
    }
}

/// The source must not name the product either — a re-export or a `use` would
/// slip past a manifest-only check if the dependency arrived transitively.
#[test]
fn no_source_file_names_the_product() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut checked = 0usize;
    for entry in std::fs::read_dir(&src).expect("src must exist") {
        let path = entry.expect("readable entry").path();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("source must be readable");
        for (number, line) in text.lines().enumerate() {
            // The doc comments explain the rule and quote the forbidden prefix,
            // so only real code counts.
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            assert!(
                !trimmed.contains("nrr_"),
                "{} line {} references the product: `{trimmed}`",
                path.display(),
                number + 1,
            );
        }
        checked += 1;
    }
    assert!(
        checked > 0,
        "no source files were checked — the test is blind"
    );
}
