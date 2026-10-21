#![allow(clippy::expect_used)]

//! `nrr-domain` is pure policy: it reaches no OS API, no store, no UI.
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
    "nrr-storage",
    "nrr-platform-api",
    "nrr-platform-windows",
    "nrr-platform-linux",
    "rusqlite",
    "windows",
    "windows-sys",
    "winapi",
];

#[test]
fn the_domain_links_no_os_store_or_ui_crate() {
    let linked = graph::linked_crates(env!("CARGO_MANIFEST_DIR"), "nrr-domain");
    let leaks = graph::leaks(&linked, FORBIDDEN);
    assert!(
        leaks.is_empty(),
        "nrr-domain links {leaks:?}. Trace with `cargo tree -p nrr-domain -i <crate>`."
    );
}

#[test]
fn the_only_workspace_crate_the_domain_links_is_the_contracts() {
    let workspace: Vec<_> = graph::linked_crates(env!("CARGO_MANIFEST_DIR"), "nrr-domain")
        .into_iter()
        .filter(|name| name.starts_with("nrr-"))
        .collect();
    assert_eq!(workspace, ["nrr-shared"]);
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
