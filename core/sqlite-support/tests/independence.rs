//! A leaf, enforced: both the service store and the GUI sidecar depend on this
//! crate, so any `nrr-*` edge out of it would hand the sidecar that crate too.

use std::path::Path;

#[test]
fn the_manifest_depends_on_no_product_crate() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let text = std::fs::read_to_string(manifest).expect("manifest");
    let mut dependency_lines = 0;
    for line in text.lines().map(str::trim) {
        if line.starts_with('#') || !line.contains('=') {
            continue;
        }
        if line.contains("version") || line.contains("path") {
            dependency_lines += 1;
        }
        assert!(
            !line.starts_with("nrr-"),
            "nrr-sqlite-support must stay a leaf: `{line}`"
        );
    }
    assert!(dependency_lines > 0, "no dependency line was checked");
}
