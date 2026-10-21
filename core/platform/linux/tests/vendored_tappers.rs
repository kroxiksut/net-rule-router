#![allow(clippy::expect_used)]

//! The vendored `tappers` copy stays a third-party crate: it reaches no product
//! crate, so the crates.io release can replace it as a version bump, and only a
//! Linux build links it, so Windows stays on `wintun-bindings`.

#[path = "../../../sqlite-support/tests/support/reachable.rs"]
mod reachable;

use std::collections::BTreeSet;
use std::process::Command;

#[test]
fn the_vendored_tun_crate_links_no_product_crate() {
    let product = reachable::reachable_product_crates("tappers");
    assert!(
        product.is_empty(),
        "the vendored tappers copy must not depend on the product, yet links {product:?}; \
         trace with `cargo tree -p tappers -i <crate>`"
    );
}

#[test]
fn the_graph_check_sees_its_transitive_dependencies() {
    // `windows-link` arrives only through `windows-sys`: seeing it shows the
    // check reads transitive edges, not the manifest.
    let reachable = reachable::reachable_packages("tappers");
    assert!(
        reachable.contains("libc") && reachable.contains("windows-link"),
        "the graph check missed a dependency of tappers: {reachable:?}"
    );
}

#[test]
fn only_a_linux_build_links_it() {
    assert!(
        workspace_packages_for("x86_64-unknown-linux-gnu").contains("tappers"),
        "the Linux build no longer links the vendored tappers copy"
    );
    assert!(
        !workspace_packages_for("x86_64-pc-windows-msvc").contains("tappers"),
        "a Windows build links tappers; Windows uses wintun-bindings. \
         Trace with `cargo tree --target x86_64-pc-windows-msvc -i tappers`"
    );
}

/// Every package the workspace links through normal and build edges when built
/// for `target`.
fn workspace_packages_for(target: &str) -> BTreeSet<String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        .args([
            "tree",
            "--workspace",
            "-e",
            "normal,build",
            "--target",
            target,
            "--prefix",
            "none",
            "--format",
            "{p}",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree must run");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}
