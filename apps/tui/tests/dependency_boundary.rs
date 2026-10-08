#![allow(clippy::expect_used)]

//! The terminal interface links no Qt, desktop, launcher or service crate, at
//! any depth: it ships in packages without a GUI, and a desktop crate one level
//! down would carry the whole desktop graph in. Checked on the resolved graph
//! from `cargo metadata`, not on the manifest.

use std::collections::{BTreeSet, HashMap, HashSet};

const FORBIDDEN: &[&str] = &[
    "nrr-application",
    "nrr-ui-support",
    "nrr-mock-backend",
    "nrr-desktop-gui",
    "nrr-desktop-tray",
    "nrr-launcher",
    "nrr-qt-host",
    "nrr-broker",
    "nrr-service-runtime",
    "nrr-windows-service",
    "nrr-linux-service",
];

/// Every crate linked into `package`, at any depth. Only normal dependencies
/// are followed (a dev-dependency never reaches the binary); platform-specific
/// edges are kept, so a crate that reaches the binary on one OS fails on all.
fn linked_crates(package: &str) -> BTreeSet<String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = std::process::Command::new(cargo)
        .args(["metadata", "--format-version", "1"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo metadata must run");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let meta: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata must be JSON");

    let name_of: HashMap<&str, &str> = meta["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .map(|pkg| {
            (
                pkg["id"].as_str().expect("id"),
                pkg["name"].as_str().expect("name"),
            )
        })
        .collect();
    let mut deps_of: HashMap<&str, Vec<&str>> = HashMap::new();
    for node in meta["resolve"]["nodes"].as_array().expect("nodes") {
        let normal = node["deps"]
            .as_array()
            .expect("deps")
            .iter()
            .filter(|dep| {
                dep["dep_kinds"]
                    .as_array()
                    .expect("dep_kinds")
                    .iter()
                    .any(|kind| kind["kind"].is_null())
            })
            .map(|dep| dep["pkg"].as_str().expect("pkg"))
            .collect();
        deps_of.insert(node["id"].as_str().expect("node id"), normal);
    }

    let root = name_of
        .iter()
        .find(|(_, name)| **name == package)
        .map(|(id, _)| *id)
        .unwrap_or_else(|| panic!("{package} not found in workspace metadata"));

    let mut linked = BTreeSet::new();
    let mut visited = HashSet::new();
    let mut queue = vec![root];
    while let Some(id) = queue.pop() {
        if !visited.insert(id) {
            continue;
        }
        for &dep in deps_of.get(id).into_iter().flatten() {
            if let Some(name) = name_of.get(dep) {
                linked.insert((*name).to_string());
            }
            queue.push(dep);
        }
    }
    linked
}

#[test]
fn the_terminal_interface_links_no_desktop_or_service_crate() {
    let linked = linked_crates("nrr-tui");
    let leaks: Vec<_> = FORBIDDEN.iter().filter(|f| linked.contains(**f)).collect();
    assert!(
        leaks.is_empty(),
        "nrr-tui links {leaks:?}. Trace with `cargo tree -p nrr-tui -i <crate>`."
    );
}

/// A detector that cannot fire proves nothing: the launcher does link desktop
/// crates, so the same walk must see them there.
#[test]
fn the_detector_sees_desktop_crates_where_they_are() {
    let linked = linked_crates("nrr-launcher");
    for expected in ["nrr-application", "nrr-ui-support", "nrr-mock-backend"] {
        assert!(
            linked.contains(expected),
            "the walk missed {expected} in the launcher; its verdict on nrr-tui is void"
        );
    }
}
