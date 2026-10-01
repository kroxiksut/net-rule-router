//! The sidecar holds GUI decoration and never routing policy; it must not link
//! the service store. The migration runner both need lives in the leaf
//! `nrr-sqlite-support` instead.

use std::path::Path;

#[test]
fn the_only_product_dependency_is_the_sqlite_leaf() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let text = std::fs::read_to_string(manifest).expect("manifest");
    let product: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && l.starts_with("nrr-"))
        .filter_map(|l| l.split('=').next().map(str::trim))
        .collect();
    assert_eq!(product, ["nrr-sqlite-support"]);
}
