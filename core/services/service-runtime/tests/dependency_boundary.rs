#![allow(clippy::expect_used)]

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
//! There are two checks, because the first one alone was defeated for
//! months by a single hop.
//!
//! 1. A string scan over this manifest: hermetic, instant, catches the
//!    obvious case.
//! 2. The real one — the whole dependency GRAPH, read from
//!    `cargo metadata`. The rule is "a forbidden crate must not end up in
//!    the service binary", and the scan could only ever say "not named on
//!    this page". It read as the stronger claim (this header used to say
//!    the check "cannot be defeated"), while `nrr-ui-support` and
//!    `nrr-mock-backend` were reaching the LocalSystem service through
//!    `nrr-application` — declared here and used nowhere.

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

/// Every crate reachable from `package`, at any depth, as cargo resolves it.
///
/// Asks cargo rather than parsing manifests by hand: the graph is the fact we
/// care about, and cargo is the only thing that knows it. Platform-specific
/// dependencies are NOT filtered out — a crate that only reaches the service on
/// one OS is still in the binary there, and this guardrail should fail on the
/// developer's machine rather than on that OS.
fn reachable_crates(package: &str) -> std::collections::BTreeSet<String> {
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

    let mut name_of = std::collections::HashMap::new();
    for pkg in meta["packages"].as_array().expect("packages") {
        name_of.insert(
            pkg["id"].as_str().expect("id").to_string(),
            pkg["name"].as_str().expect("name").to_string(),
        );
    }
    let mut deps_of: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for node in meta["resolve"]["nodes"].as_array().expect("nodes") {
        let id = node["id"].as_str().expect("node id").to_string();
        let deps = node["deps"]
            .as_array()
            .expect("deps")
            .iter()
            .map(|d| d["pkg"].as_str().expect("pkg").to_string())
            .collect();
        deps_of.insert(id, deps);
    }

    let root = name_of
        .iter()
        .find(|(_, name)| name.as_str() == package)
        .map(|(id, _)| id.clone())
        .unwrap_or_else(|| panic!("{package} not found in workspace metadata"));

    let mut seen = std::collections::BTreeSet::new();
    let mut queue = vec![root];
    let mut visited = std::collections::HashSet::new();
    while let Some(id) = queue.pop() {
        if !visited.insert(id.clone()) {
            continue;
        }
        for dep in deps_of.get(&id).into_iter().flatten() {
            if let Some(name) = name_of.get(dep) {
                seen.insert(name.clone());
            }
            queue.push(dep.clone());
        }
    }
    seen
}

#[test]
fn no_ui_crate_reaches_the_service_through_any_chain() {
    // The check the manifest scan only pretended to be. `nrr-service-runtime`
    // and the two service binaries are all covered: a forbidden crate that
    // reaches any of them is in that binary.
    for package in [
        "nrr-service-runtime",
        "nrr-windows-service",
        "nrr-linux-service",
    ] {
        let reachable = reachable_crates(package);
        let leaks: Vec<_> = FORBIDDEN_DEPS
            .iter()
            .filter(|f| reachable.contains(**f))
            .collect();
        assert!(
            leaks.is_empty(),
            "{package} reaches UI/preview/binary crates transitively: {leaks:?}. \
             Trace the chain with `cargo tree -p {package} -i <crate>`.",
        );
    }
}

#[test]
fn the_transitive_check_can_actually_fail() {
    // A guard that never fires is indistinguishable from no guard — which is
    // exactly how the manifest scan passed while the leak was live. Positive
    // control: `nrr-application` genuinely does reach the UI and preview
    // crates, so the detector must see them there.
    let reachable = reachable_crates("nrr-application");
    for expected in ["nrr-ui-support", "nrr-mock-backend"] {
        assert!(
            reachable.contains(expected),
            "the detector failed to see {expected} where it demonstrably is; \
             the service-side result cannot be trusted either",
        );
    }
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
