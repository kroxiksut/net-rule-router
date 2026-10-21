//! The packages a crate links, as cargo resolves them: a renamed, table-form,
//! path or transitive dependency shows up under its real name, which no scan
//! of the manifest text can promise.

use std::collections::BTreeSet;
use std::process::Command;

/// Every package `package` reaches through normal and build edges on any
/// target, itself excluded. Dev-dependencies never reach the library.
pub fn reachable_packages(package: &str) -> BTreeSet<String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        .args([
            "tree",
            "-p",
            package,
            "-e",
            "normal,build",
            "--target",
            "all",
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
        .filter(|name| *name != package)
        .map(str::to_owned)
        .collect()
}

/// The product crates among them.
pub fn reachable_product_crates(package: &str) -> Vec<String> {
    reachable_packages(package)
        .into_iter()
        .filter(|name| name.starts_with("nrr-"))
        .collect()
}
