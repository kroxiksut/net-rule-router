#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Help > Documentation and the terminal's About open a page that is there: the
//! offline one in the reader's language when the package carries it, English
//! when that language has none, the project's page online when nothing is
//! installed — never a missing file or a 404.

use std::path::Path;

use nrr_shared::docs_location::{docs_index, docs_indexes, DocsIndex, DOCS_TRANSLATIONS};

const URL: &str = "https://example.invalid/owner/project";

fn page(root: &Path, relative: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, "<!doctype html>").unwrap();
}

#[test]
fn the_offline_page_in_the_readers_language_comes_first() {
    let package = tempfile::tempdir().unwrap();
    page(package.path(), "docs/en/index.html");
    page(package.path(), "docs/ru/index.html");
    assert_eq!(
        docs_index([package.path()], URL, "ru-RU"),
        DocsIndex::Local(package.path().join("docs").join("ru").join("index.html"))
    );
}

#[test]
fn a_language_without_offline_pages_reads_them_in_english() {
    let package = tempfile::tempdir().unwrap();
    page(package.path(), "docs/en/index.html");
    // A folder without its start page is not a language.
    std::fs::create_dir_all(package.path().join("docs/ru")).unwrap();
    for language in ["ru", "de", ""] {
        assert_eq!(
            docs_index([package.path()], URL, language),
            DocsIndex::Local(package.path().join("docs").join("en").join("index.html")),
            "{language:?}"
        );
    }
}

#[test]
fn without_offline_pages_the_project_pages_open_online() {
    let checkout = tempfile::tempdir().unwrap();
    // A checkout has the Markdown, not the pages.
    page(checkout.path(), "docs/en/quickstart.md");
    assert_eq!(
        docs_index([checkout.path()], URL, "ru"),
        DocsIndex::Online(format!("{URL}/blob/main/docs/README.ru.md"))
    );
    assert_eq!(
        docs_index([checkout.path()], URL, "de"),
        DocsIndex::Online(format!("{URL}/blob/main/docs/README.md"))
    );
}

#[test]
fn the_package_beside_the_program_wins_over_a_later_root() {
    let package = tempfile::tempdir().unwrap();
    let checkout = tempfile::tempdir().unwrap();
    page(package.path(), "docs/en/index.html");
    page(checkout.path(), "docs/en/index.html");
    page(checkout.path(), "docs/ru/index.html");
    let found = docs_indexes([package.path(), checkout.path()], URL);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        found[0].1,
        DocsIndex::Local(package.path().join("docs").join("en").join("index.html"))
    );
}

/// The online index of a language exists in the repository: a translation
/// added without being listed would open in English, one removed would 404.
#[test]
fn every_listed_translation_has_its_index_in_the_repository() {
    let docs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs");
    let mut found: Vec<String> = std::fs::read_dir(&docs)
        .expect("docs/")
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_owned();
            let id = name.strip_prefix("README.")?.strip_suffix(".md")?;
            (!id.is_empty()).then(|| id.to_owned())
        })
        .collect();
    found.sort();
    let mut listed: Vec<String> = DOCS_TRANSLATIONS.iter().map(|s| (*s).to_owned()).collect();
    listed.sort();
    assert_eq!(found, listed);
}
