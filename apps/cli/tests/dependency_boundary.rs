#![allow(clippy::expect_used)]

//! The console links the IPC client and nothing of the desktop: no preview
//! data, no UI preferences, no GUI crate. Checked on the resolved graph from
//! `cargo metadata`, because the edge that once carried those crates into this
//! binary was an unused dependency one level down, invisible in this manifest.

use std::collections::{BTreeSet, HashMap, HashSet};

const FORBIDDEN: &[&str] = &[
    "nrr-application",
    "nrr-ui-support",
    "nrr-mock-backend",
    "nrr-desktop-gui",
    "nrr-desktop-tray",
    "nrr-launcher",
    "nrr-qt-host",
];

/// Every crate linked into `package`, at any depth. Only normal dependencies
/// are followed: a dependency's dev-dependencies never reach this binary, and
/// the client's test-only edge to the service runtime would otherwise drag the
/// whole service graph in. Platform-specific edges are kept, so a crate that
/// reaches the console on one OS fails here on every OS.
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
fn the_console_links_no_desktop_or_preview_crate() {
    for package in ["nrr-cli", "nrr-ipc-client"] {
        let linked = linked_crates(package);
        let leaks: Vec<_> = FORBIDDEN.iter().filter(|f| linked.contains(**f)).collect();
        assert!(
            leaks.is_empty(),
            "{package} links {leaks:?}. Trace with `cargo tree -p {package} -i <crate>`."
        );
    }
}

#[test]
fn the_ipc_client_links_the_wire_contracts_only() {
    let workspace_crates: Vec<_> = linked_crates("nrr-ipc-client")
        .into_iter()
        .filter(|name| name.starts_with("nrr-"))
        .collect();
    assert_eq!(workspace_crates, ["nrr-shared"]);
}

/// A detector that cannot fire proves nothing: the launcher does link the
/// desktop crates, so the same walk must see them there.
#[test]
fn the_detector_sees_desktop_crates_where_they_are() {
    let linked = linked_crates("nrr-launcher");
    for expected in ["nrr-application", "nrr-ui-support", "nrr-mock-backend"] {
        assert!(
            linked.contains(expected),
            "the walk missed {expected} in the launcher; its verdict on the console is void"
        );
    }
}
