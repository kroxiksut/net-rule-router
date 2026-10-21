#![allow(clippy::expect_used)]

//! The sidecar holds GUI decoration and never routing policy; it must not link
//! the service store. The migration runner both need lives in the leaf
//! `nrr-sqlite-support` instead.

#[path = "../../sqlite-support/tests/support/reachable.rs"]
mod reachable;

#[test]
fn the_only_product_crate_it_links_is_the_sqlite_leaf() {
    let product = reachable::reachable_product_crates("nrr-storage-sidecar");
    assert_eq!(
        product,
        ["nrr-sqlite-support"],
        "trace an unexpected crate with `cargo tree -p nrr-storage-sidecar -i <crate>`"
    );
}

#[test]
fn the_graph_check_sees_crates_the_manifest_never_names() {
    // SQLite's bindings reach the sidecar only through rusqlite: a check that
    // sees them reads transitive edges, not the manifest.
    let reachable = reachable::reachable_packages("nrr-storage-sidecar");
    assert!(
        reachable.contains("libsqlite3-sys"),
        "the graph check missed a transitive dependency: {reachable:?}"
    );
}
