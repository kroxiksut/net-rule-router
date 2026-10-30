#![allow(clippy::expect_used, clippy::unwrap_used)]

//! The documentation the packages carry converts as it stands: one dead link
//! in any page fails here rather than in the packaging run of a release.

use std::path::Path;

#[test]
fn the_shipped_documentation_converts_with_an_index_per_language() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = tempfile::tempdir().unwrap();
    let url = nrr_shared::gui_shell_v1().about.project_url;
    nrr_docs_html::build(&repo, out.path(), url).expect("docs/ converts");
    for language in ["en", "ru"] {
        let index = out.path().join(language).join("index.html");
        let html = std::fs::read_to_string(&index).expect("index page");
        assert!(html.contains(&format!(r#"<html lang="{language}">"#)));
        assert!(!html.contains("<script"));
    }
}
