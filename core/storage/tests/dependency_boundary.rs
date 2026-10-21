#![allow(clippy::expect_used)]

//! `nrr-storage` rests on the domain, the platform port and the SQLite leaf.
//! Checked on the resolved graph from `cargo metadata`, not on manifest text.

#[path = "../../dependency_graph_gate.rs"]
mod graph;

const FORBIDDEN: &[&str] = &[
    "nrr-application",
    "nrr-ui-support",
    "nrr-mock-backend",
    "nrr-desktop-gui",
    "nrr-desktop-tray",
    "nrr-launcher",
    "nrr-qt-host",
    "nrr-service-runtime",
    "nrr-platform-windows",
    "nrr-platform-linux",
];

#[test]
fn storage_links_no_ui_service_or_os_crate() {
    let linked = graph::linked_crates(env!("CARGO_MANIFEST_DIR"), "nrr-storage");
    let leaks = graph::leaks(&linked, FORBIDDEN);
    assert!(
        leaks.is_empty(),
        "nrr-storage links {leaks:?}. Trace with `cargo tree -p nrr-storage -i <crate>`."
    );
}

/// The contracts reach storage only through the domain: a direct edge would
/// let wire types shape the schema.
#[test]
fn storage_does_not_declare_the_contracts_itself() {
    let direct = graph::direct_crates(env!("CARGO_MANIFEST_DIR"), "nrr-storage");
    assert!(!direct.contains("nrr-shared"), "direct edges: {direct:?}");
    assert!(
        direct.contains("nrr-domain"),
        "scan saw nothing: {direct:?}"
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
            "the walk missed {expected} in the GUI library; its verdicts here are void"
        );
    }
}
