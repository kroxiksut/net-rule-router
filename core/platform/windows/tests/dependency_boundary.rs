//! Dependency boundary tests.
//!
//! Mirrors the pattern from `nrr-service-runtime/tests/dependency_boundary.rs`.
//! Reads Cargo.toml at compile time and rejects any forbidden dependency.

const CARGO_TOML: &str = include_str!("../Cargo.toml");

/// Forbidden crate names — any line in Cargo.toml containing these is rejected.
const FORBIDDEN: &[&str] = &[
    "nrr-application",
    "nrr-service-runtime",
    "nrr-desktop-gui",
    "nrr-desktop-tray",
    "nrr-launcher",
    "nrr-mock-backend",
    "nrr-ui-support",
];

#[test]
fn manifest_is_parseable_by_naive_scanner() {
    // Verify the include_str! succeeded and the file is non-empty.
    assert!(
        CARGO_TOML.contains("[package]"),
        "Cargo.toml missing [package] section"
    );
    assert!(
        CARGO_TOML.contains("nrr-platform-windows"),
        "Cargo.toml missing expected package name"
    );
}

#[test]
fn no_forbidden_dependencies_in_manifest() {
    for dep in FORBIDDEN {
        // Check every non-comment line in the file.
        for (line_num, line) in CARGO_TOML.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            assert!(
                !trimmed.contains(dep),
                "Forbidden dependency '{dep}' found in Cargo.toml at line {}: {:?}",
                line_num + 1,
                line
            );
        }
    }
}
