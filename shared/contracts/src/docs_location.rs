//! Where the user documentation is: the offline pages a package carries beside
//! its executables, or the project's pages online when it carries none (a
//! build from the checkout, or an install without the documentation).

use std::path::{Path, PathBuf};

/// The package folder holding the offline pages, one subfolder per language.
pub const DOCS_FOLDER: &str = "docs";
/// A language's start page inside its folder.
pub const DOCS_INDEX_PAGE: &str = "index.html";
/// The language whose documentation is complete; the answer for any other.
pub const DOCS_CANONICAL_LANGUAGE: &str = "en";
/// Languages with a translated index in the repository, `docs/README.<id>.md`
/// (the English one is `docs/README.md`). Held to the files by a test.
pub const DOCS_TRANSLATIONS: &[&str] = &["ru"];

/// One language's documentation start page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocsIndex {
    Local(PathBuf),
    Online(String),
}

impl DocsIndex {
    /// The path or the URL, as a reader would type it.
    pub fn display(&self) -> String {
        match self {
            Self::Local(path) => path.display().to_string(),
            Self::Online(url) => url.clone(),
        }
    }
}

/// The start page of every documentation language, sorted, English among them:
/// the offline pages of the first root that carries any, otherwise online.
pub fn docs_indexes<'a>(
    package_roots: impl IntoIterator<Item = &'a Path>,
    project_url: &str,
) -> Vec<(String, DocsIndex)> {
    let local = package_roots
        .into_iter()
        .map(local_indexes)
        .find(|found| found.iter().any(|(id, _)| id == DOCS_CANONICAL_LANGUAGE));
    match local {
        Some(found) => found
            .into_iter()
            .map(|(id, path)| (id, DocsIndex::Local(path)))
            .collect(),
        None => {
            let mut online: Vec<(String, DocsIndex)> = std::iter::once(DOCS_CANONICAL_LANGUAGE)
                .chain(DOCS_TRANSLATIONS.iter().copied())
                .map(|id| {
                    (
                        id.to_owned(),
                        DocsIndex::Online(online_index(project_url, id)),
                    )
                })
                .collect();
            online.sort_by(|a, b| a.0.cmp(&b.0));
            online
        }
    }
}

/// The start page for `language` (`ru`, `ru-RU`, `en_US`), English where that
/// language has none.
pub fn docs_index<'a>(
    package_roots: impl IntoIterator<Item = &'a Path>,
    project_url: &str,
    language: &str,
) -> DocsIndex {
    let indexes = docs_indexes(package_roots, project_url);
    docs_index_in(&indexes, language)
        .cloned()
        .unwrap_or_else(|| DocsIndex::Online(online_index(project_url, DOCS_CANONICAL_LANGUAGE)))
}

/// The start page for `language` among `indexes` (from [`docs_indexes`]),
/// English where that language has none.
pub fn docs_index_in<'a>(
    indexes: &'a [(String, DocsIndex)],
    language: &str,
) -> Option<&'a DocsIndex> {
    let wanted = primary_subtag(language);
    indexes
        .iter()
        .find(|(id, _)| *id == wanted)
        .or_else(|| indexes.iter().find(|(id, _)| id == DOCS_CANONICAL_LANGUAGE))
        .map(|(_, index)| index)
}

fn primary_subtag(language: &str) -> String {
    language
        .split(['-', '_'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// Language folders of `<root>/docs` that hold a start page.
fn local_indexes(root: &Path) -> Vec<(String, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(root.join(DOCS_FOLDER)) else {
        return Vec::new();
    };
    let mut found: Vec<(String, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let id = entry.file_name().to_str()?.to_owned();
            let page = entry.path().join(DOCS_INDEX_PAGE);
            (is_language_id(&id) && page.is_file()).then_some((id, page))
        })
        .collect();
    found.sort();
    found
}

fn is_language_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 8 && id.bytes().all(|b| b.is_ascii_lowercase())
}

fn online_index(project_url: &str, language: &str) -> String {
    let base = project_url.trim_end_matches('/');
    if language == DOCS_CANONICAL_LANGUAGE {
        format!("{base}/blob/main/docs/README.md")
    } else {
        format!("{base}/blob/main/docs/README.{language}.md")
    }
}
