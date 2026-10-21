#![allow(clippy::expect_used)]

//! `nrr-platform-linux` is a mechanism crate: no GUI, tray, service or preview crate.
//! Checked on the resolved graph from `cargo metadata`, not on manifest text.

#[path = "../../../dependency_graph_gate.rs"]
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
];

#[test]
fn the_linux_platform_links_no_ui_service_or_windows_crate() {
    let linked = graph::linked_crates(env!("CARGO_MANIFEST_DIR"), "nrr-platform-linux");
    let leaks = graph::leaks(&linked, FORBIDDEN);
    assert!(
        leaks.is_empty(),
        "nrr-platform-linux links {leaks:?}. Trace with `cargo tree -p nrr-platform-linux -i <crate>`."
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
