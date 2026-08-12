//! Compile-time guardrail. Reads this crate's own
//! `Cargo.toml` and refuses to compile/run if any forbidden crate
//! sneaks into `[dependencies]` or `[dev-dependencies]`.
//!
//! The forbidden list covers everything that is either UI-only or that
//! would create a cycle (GUI/tray/launcher binaries) or that bypasses
//! the production data path (mock-backend preview providers). Adding a
//! new crate to the deny list takes one line; removing one requires
//! explicit reasoning in CLAUDE.md plus a SECURITY review.
//!
//! The check is intentionally a string scan over the manifest rather
//! than a `cargo metadata` call: it is hermetic, instant, and cannot be
//! defeated by a `default-features = false` workaround because a
//! forbidden crate cannot appear in the manifest at all.

const MANIFEST: &str = include_str!("../Cargo.toml");

/// Crates the service runtime must never depend on. Each entry is the
/// `name` field of a `[dependencies]` / `[dev-dependencies]` block.
const FORBIDDEN_DEPS: &[&str] = &[
    "nrr-ui-support",
    "nrr-mock-backend",
    "nrr-desktop-gui",
    "nrr-desktop-tray",
    "nrr-launcher",
    "nrr-qt-host",
];

/// Returns the dependency names declared in the manifest. Naive
/// line-based scan: looks for `name = { … }` or `name = "…"` at the
/// start of a non-comment line inside a `[dependencies]` /
/// `[dev-dependencies]` table. Sufficient for the Cargo.toml shapes we
/// hand-write in this workspace; would need a TOML parser if we ever
/// generated manifests programmatically.
fn declared_dependency_names() -> Vec<String> {
    let mut in_dep_table = false;
    let mut names = Vec::new();
    for raw_line in MANIFEST.lines() {
        let line = raw_line.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_dep_table = matches!(
                line,
                "[dependencies]"
                    | "[dev-dependencies]"
                    | "[build-dependencies]"
                    | "[target.'cfg(windows)'.dependencies]"
                    | "[target.\"cfg(windows)\".dependencies]"
                    | "[target.'cfg(not(windows))'.dependencies]"
                    | "[target.\"cfg(not(windows))\".dependencies]"
            );
            continue;
        }
        if !in_dep_table || line.is_empty() {
            continue;
        }
        if let Some(eq_idx) = line.find('=') {
            let name = line[..eq_idx].trim().trim_matches('"');
            if !name.is_empty() {
                names.push(name.to_string());
            }
        }
    }
    names
}

#[test]
fn no_ui_dependencies_in_manifest() {
    let names = declared_dependency_names();
    let leaks: Vec<_> = names
        .iter()
        .filter(|n| FORBIDDEN_DEPS.iter().any(|forbidden| forbidden == n))
        .collect();
    assert!(
        leaks.is_empty(),
        "nrr-service-runtime must not depend on UI/preview/binary crates; \
         leaks = {leaks:?}; deny-list = {FORBIDDEN_DEPS:?}"
    );
}

#[test]
fn manifest_is_parseable_by_naive_scanner() {
    // Defence-in-depth: if the manifest grows a shape the scanner
    // doesn't understand (multi-line inline tables across blank lines,
    // weird whitespace), the scan can silently return zero names and
    // the deny-list becomes a no-op. Make sure we always see the
    // dependencies we know exist.
    let names = declared_dependency_names();
    for required in [
        "nrr-application",
        "nrr-diagnostics",
        "nrr-domain",
        "nrr-platform-api",
        "nrr-platform-windows",
        "nrr-shared",
        "nrr-storage",
    ] {
        assert!(
            names.iter().any(|n| n == required),
            "scanner missed required dependency {required:?}; saw {names:?}"
        );
    }
}
