//! The resolved dependency graph of a workspace crate, shared by the
//! `tests/dependency_boundary.rs` gates through `#[path]`. A manifest scan only
//! proves a name is absent from one page; the graph is what ends up linked.
#![allow(dead_code, clippy::expect_used)]

use std::collections::{BTreeSet, HashMap, HashSet};

struct Graph {
    meta: serde_json::Value,
}

fn load(manifest_dir: &str) -> Graph {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = std::process::Command::new(cargo)
        .args(["metadata", "--format-version", "1"])
        .current_dir(manifest_dir)
        .output()
        .expect("cargo metadata must run");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Graph {
        meta: serde_json::from_slice(&output.stdout).expect("cargo metadata must be JSON"),
    }
}

impl Graph {
    fn names(&self) -> HashMap<&str, &str> {
        self.meta["packages"]
            .as_array()
            .expect("packages")
            .iter()
            .map(|p| {
                (
                    p["id"].as_str().expect("id"),
                    p["name"].as_str().expect("name"),
                )
            })
            .collect()
    }

    /// Normal and build edges per node. Dev edges never reach a shipped binary,
    /// and following them would drag a test-only edge's whole graph in.
    /// Platform-specific edges are kept: a crate that reaches the binary on one
    /// OS must fail on the developer's machine too.
    fn edges(&self) -> HashMap<&str, Vec<&str>> {
        let mut deps_of = HashMap::new();
        for node in self.meta["resolve"]["nodes"].as_array().expect("nodes") {
            let linked = node["deps"]
                .as_array()
                .expect("deps")
                .iter()
                .filter(|dep| {
                    dep["dep_kinds"]
                        .as_array()
                        .expect("dep_kinds")
                        .iter()
                        .any(|k| k["kind"].as_str() != Some("dev"))
                })
                .map(|dep| dep["pkg"].as_str().expect("pkg"))
                .collect();
            deps_of.insert(node["id"].as_str().expect("node id"), linked);
        }
        deps_of
    }

    fn root<'a>(&'a self, names: &HashMap<&'a str, &'a str>, package: &str) -> &'a str {
        names
            .iter()
            .find(|(_, name)| **name == package)
            .map(|(id, _)| *id)
            .unwrap_or_else(|| panic!("{package} not found in workspace metadata"))
    }
}

/// Every crate linked into `package`, at any depth.
pub fn linked_crates(manifest_dir: &str, package: &str) -> BTreeSet<String> {
    let graph = load(manifest_dir);
    let names = graph.names();
    let edges = graph.edges();
    let mut linked = BTreeSet::new();
    let mut visited = HashSet::new();
    let mut queue = vec![graph.root(&names, package)];
    while let Some(id) = queue.pop() {
        if !visited.insert(id) {
            continue;
        }
        for &dep in edges.get(id).into_iter().flatten() {
            if let Some(name) = names.get(dep) {
                linked.insert((*name).to_string());
            }
            queue.push(dep);
        }
    }
    linked
}

/// The crates `package` itself declares (normal and build kinds).
pub fn direct_crates(manifest_dir: &str, package: &str) -> BTreeSet<String> {
    let graph = load(manifest_dir);
    let names = graph.names();
    let edges = graph.edges();
    edges
        .get(graph.root(&names, package))
        .into_iter()
        .flatten()
        .filter_map(|dep| names.get(dep).map(|n| (*n).to_string()))
        .collect()
}

/// The members of `forbidden` that `linked` contains.
pub fn leaks<'a>(linked: &BTreeSet<String>, forbidden: &[&'a str]) -> Vec<&'a str> {
    forbidden
        .iter()
        .copied()
        .filter(|f| linked.contains(*f))
        .collect()
}
