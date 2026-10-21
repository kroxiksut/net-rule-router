#![allow(clippy::expect_used)]

//! A leaf, enforced: both the service store and the GUI sidecar depend on this
//! crate, so any `nrr-*` edge out of it would hand the sidecar that crate too.

#[path = "support/reachable.rs"]
mod reachable;

#[test]
fn it_links_no_product_crate_at_any_depth() {
    let product = reachable::reachable_product_crates("nrr-sqlite-support");
    assert!(
        product.is_empty(),
        "nrr-sqlite-support must stay a leaf, yet links {product:?}; \
         trace with `cargo tree -p nrr-sqlite-support -i <crate>`"
    );
}

#[test]
fn the_graph_check_sees_crates_the_manifest_never_names() {
    // A guard that cannot fire proves nothing: SQLite's own bindings arrive
    // only through rusqlite, so seeing them shows transitive edges are read.
    let reachable = reachable::reachable_packages("nrr-sqlite-support");
    assert!(
        reachable.contains("libsqlite3-sys"),
        "the graph check missed a transitive dependency: {reachable:?}"
    );
}
