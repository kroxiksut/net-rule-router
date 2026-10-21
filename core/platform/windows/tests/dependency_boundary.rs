//! Dependency boundary tests.
//!
//! The manifest scan catches the obvious case; the resolved graph from
//! `cargo metadata` catches a crate that arrives through an edge one level down.

#[path = "../../../dependency_graph_gate.rs"]
mod graph;

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

#[test]
fn the_windows_platform_links_no_ui_or_service_crate_at_any_depth() {
    let linked = graph::linked_crates(env!("CARGO_MANIFEST_DIR"), "nrr-platform-windows");
    let leaks = graph::leaks(&linked, FORBIDDEN);
    assert!(
        leaks.is_empty(),
        "nrr-platform-windows links {leaks:?}. Trace with `cargo tree -p nrr-platform-windows -i <crate>`."
    );
}

/// A detector that cannot fire proves nothing: the GUI library does link the
/// UI crates, so the same walk must see them there.
#[test]
fn the_detector_sees_ui_crates_where_they_are() {
    let linked = graph::linked_crates(env!("CARGO_MANIFEST_DIR"), "nrr-desktop-gui");
    for expected in ["nrr-ui-support", "nrr-mock-backend"] {
        assert!(
            linked.contains(expected),
            "the walk missed {expected} in the GUI library; its verdict here is void"
        );
    }
}
