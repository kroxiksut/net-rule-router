#![allow(clippy::expect_used)]

//! English documentation is the complete set; any other language is optional.
//! A page written only in another language leaves an English reader, and
//! everyone the missing translation falls back to, with no page at all.

use std::path::{Path, PathBuf};

/// A locale id as a directory or file-name tag names it: `ru`, `de`,
/// `pt-BR`, `zh-Hans`. `legal` or `images` are folders, not languages.
fn is_language_tag(tag: &str) -> bool {
    let (primary, region) = match tag.split_once('-') {
        Some((primary, region)) => (primary, Some(region)),
        None => (tag, None),
    };
    (2..=3).contains(&primary.len())
        && primary.bytes().all(|b| b.is_ascii_lowercase())
        && region.is_none_or(|r| {
            (2..=4).contains(&r.len()) && r.bytes().all(|b| b.is_ascii_alphanumeric())
        })
}

fn markdown_files(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            markdown_files(&path, found);
        } else if path.extension().is_some_and(|e| e == "md") {
            found.push(path);
        }
    }
}

/// Every page under `docs` with no English twin, relative to `docs`: one in
/// `docs/<lang>/` needs the same path under `docs/en/`, and `name.<lang>.md`
/// needs `name.md` or `name.en.md` beside it.
fn pages_without_english(docs: &Path) -> Vec<String> {
    let mut pages = Vec::new();
    markdown_files(docs, &mut pages);
    let mut missing: Vec<String> = pages
        .iter()
        .filter_map(|page| {
            let relative = page.strip_prefix(docs).ok()?;
            let mut parts = relative.components();
            let first = parts.next()?.as_os_str().to_str()?;
            let in_language_dir =
                relative.components().count() > 1 && first != "en" && is_language_tag(first);
            let twins: Vec<PathBuf> = if in_language_dir {
                vec![docs.join("en").join(parts.as_path())]
            } else {
                let name = page.file_name()?.to_str()?.strip_suffix(".md")?;
                let (stem, tag) = name.rsplit_once('.')?;
                if tag == "en" || !is_language_tag(tag) {
                    return None;
                }
                let dir = page.parent()?;
                vec![
                    dir.join(format!("{stem}.md")),
                    dir.join(format!("{stem}.en.md")),
                ]
            };
            (!twins.iter().any(|twin| twin.is_file()))
                .then(|| relative.to_string_lossy().replace('\\', "/"))
        })
        .collect();
    missing.sort();
    missing
}

#[test]
fn every_published_page_has_an_english_version() {
    let docs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs");
    assert!(docs.join("en").is_dir(), "{}", docs.display());
    assert_eq!(
        pages_without_english(&docs),
        Vec::<String>::new(),
        "write the English page first; other languages are optional"
    );
}

/// The check sees a page that has only a translation, in either layout, and
/// passes what English covers or what is not a language at all.
#[test]
fn a_page_with_only_a_translation_is_reported() {
    let root = tempfile::tempdir().expect("tempdir");
    let docs = root.path();
    let write = |relative: &str| {
        let path = docs.join(relative);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
        std::fs::write(path, "# page\n").expect("write");
    };
    write("en/quickstart.md");
    write("ru/quickstart.md");
    write("en/guides/vpn.md");
    write("ru/guides/vpn.md");
    write("de/routing.md");
    write("pt-BR/guides/only-here.md");
    write("ru/images/notes.md");
    write("legal/terms.md");
    write("legal/eula.en.md");
    write("legal/eula.ru.md");
    write("README.md");
    write("README.ru.md");
    write("privacy.de.md");
    write("changes.v2.md");
    assert_eq!(
        pages_without_english(docs),
        [
            "de/routing.md",
            "privacy.de.md",
            "pt-BR/guides/only-here.md",
            "ru/images/notes.md",
        ]
    );
}
