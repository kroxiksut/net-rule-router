#![allow(clippy::expect_used, clippy::unwrap_used)]

//! What a reader of the offline documentation is promised: every link lands on
//! a page or picture that is there, at the heading it names, in their language
//! when it exists and in English otherwise; a link the converter cannot keep
//! working stops the build instead of shipping a dead end.

use std::fs;
use std::path::Path;

use nrr_docs_html::build;

const REPO_URL: &str = "https://example.invalid/owner/project";

fn write(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn read(root: &Path, relative: &str) -> String {
    fs::read_to_string(root.join(relative)).unwrap_or_else(|e| panic!("{relative}: {e}"))
}

/// A small documentation tree: English index and two pages, a Russian index
/// and one translated page, an agreement per language and one picture.
fn site() -> tempfile::TempDir {
    let repo = tempfile::tempdir().unwrap();
    let root = repo.path();
    write(
        root,
        "docs/README.md",
        "# Docs\n\n**English** · [Русский](README.ru.md)\n\n\
         | Page | About |\n|---|---|\n| [Start](en/quickstart.md#first-steps) | x |\n\
         | [Agreement](legal/eula.en.md) | y |\n\n[Security](../SECURITY.md#trust) [presets](../presets/)\n",
    );
    write(
        root,
        "docs/README.ru.md",
        "# Документация\n\n[English](README.md) · **Русский**\n\n\
         [Старт](ru/quickstart.md) [Соглашение](legal/eula.ru.md)\n",
    );
    write(
        root,
        "docs/en/quickstart.md",
        "# Quick start\n\n## First steps\n\n![Rules](images/rules.png)\n\n\
         [Priority](priority.md#zones) [index](../README.md) [here](#first-steps)\n",
    );
    write(root, "docs/en/priority.md", "# Priority\n\n## Zones\n");
    write(
        root,
        "docs/ru/quickstart.md",
        "# Быстрый старт\n\n[Приоритет](priority.md) [в начало](../README.ru.md)\n",
    );
    write(root, "docs/en/images/rules.png", "png");
    write(root, "docs/legal/eula.en.md", "# Agreement\n");
    write(root, "docs/legal/eula.ru.md", "# Соглашение\n");
    write(root, "SECURITY.md", "# Security\n\n## Trust\n");
    write(root, "presets/demo.txt", "");
    repo
}

fn built(repo: &Path) -> tempfile::TempDir {
    let out = tempfile::tempdir().unwrap();
    build(repo, out.path(), REPO_URL).expect("the documentation converts");
    out
}

#[test]
fn a_link_to_another_page_opens_its_html_twin_at_the_same_heading() {
    let repo = site();
    let out = built(repo.path());
    let index = read(out.path(), "en/index.html");
    assert!(
        index.contains(r#"href="quickstart.html#first-steps""#),
        "{index}"
    );
    assert!(index.contains(r#"href="eula.html""#), "{index}");
    assert!(index.contains(r#"href="../ru/index.html""#), "{index}");
    let page = read(out.path(), "en/quickstart.html");
    assert!(page.contains(r#"href="priority.html#zones""#), "{page}");
    assert!(page.contains(r#"href="index.html""#), "{page}");
    assert!(page.contains(r##"href="#first-steps""##), "{page}");
    assert!(page.contains(r#"<h2 id="first-steps">"#), "{page}");
    assert!(read(out.path(), "ru/eula.html").contains("Соглашение"));
}

#[test]
fn heading_ids_match_github_so_existing_anchors_keep_working() {
    let repo = site();
    write(
        repo.path(),
        "docs/en/priority.md",
        "# Priority\n\n## Zones\n\n## Второй раздел\n\n## Notes\n\n## Notes ##\n\n\
         ## `code` and **bold**: done!\n\n## [Linked](quickstart.md) title\n",
    );
    let out = built(repo.path());
    let page = read(out.path(), "en/priority.html");
    for id in [
        "zones",
        "второй-раздел",
        "notes",
        "notes-1",
        "code-and-bold-done",
        "linked-title",
    ] {
        assert!(page.contains(&format!(r#"id="{id}""#)), "{id} in {page}");
    }
}

#[test]
fn a_broken_link_or_heading_stops_the_build_naming_the_page() {
    for (body, expected) in [
        ("[gone](gone.md)", "gone.md"),
        ("[bad](priority.md#no-such-heading)", "no-such-heading"),
        ("[self](#nope)", "#nope"),
        ("![lost](images/lost.png)", "images/lost.png"),
        ("[escape](../../../outside.md)", "outside.md"),
        ("[case](Priority.md)", "Priority.md"),
    ] {
        let repo = site();
        write(
            repo.path(),
            "docs/en/broken.md",
            &format!("# Broken\n\n{body}\n"),
        );
        let out = tempfile::tempdir().unwrap();
        let error = build(repo.path(), out.path(), REPO_URL)
            .expect_err(body)
            .to_string();
        assert!(
            error.contains("docs/en/broken.md") && error.contains(expected),
            "{body}: {error}"
        );
    }
}

#[test]
fn a_page_without_a_translation_is_read_in_english() {
    let repo = site();
    let out = built(repo.path());
    let ru = read(out.path(), "ru/quickstart.html");
    assert!(ru.contains(r#"href="../en/priority.html""#), "{ru}");
    assert!(ru.contains(r#"href="index.html""#), "{ru}");
    // The English page with no Russian twin switches to the Russian index.
    let en = read(out.path(), "en/priority.html");
    assert!(en.contains(r#"href="../ru/index.html""#), "{en}");
    let en_start = read(out.path(), "en/quickstart.html");
    assert!(
        en_start.contains(r#"href="../ru/quickstart.html""#),
        "{en_start}"
    );
}

#[test]
fn pictures_travel_with_the_pages() {
    let repo = site();
    let out = built(repo.path());
    let page = read(out.path(), "en/quickstart.html");
    assert!(page.contains(r#"src="images/rules.png""#), "{page}");
    assert_eq!(read(out.path(), "en/images/rules.png"), "png");
}

#[test]
fn a_link_outside_the_documentation_goes_to_the_project_online() {
    let repo = site();
    let out = built(repo.path());
    let index = read(out.path(), "en/index.html");
    assert!(
        index.contains(&format!(r#"href="{REPO_URL}/blob/main/SECURITY.md#trust""#)),
        "{index}"
    );
    assert!(
        index.contains(&format!(r#"href="{REPO_URL}/tree/main/presets/""#)),
        "{index}"
    );
}

#[test]
fn a_link_inside_raw_html_is_refused_rather_than_left_pointing_at_markdown() {
    let repo = site();
    write(
        repo.path(),
        "docs/en/raw.md",
        "# Raw\n\n<a href=\"priority.md\">priority</a>\n",
    );
    let out = tempfile::tempdir().unwrap();
    let error = build(repo.path(), out.path(), REPO_URL)
        .expect_err("raw link")
        .to_string();
    assert!(error.contains("docs/en/raw.md"), "{error}");
}

#[test]
fn pages_left_from_an_earlier_build_are_never_mixed_in() {
    let repo = site();
    let out = tempfile::tempdir().unwrap();
    write(out.path(), "en/removed-page.html", "old");
    assert!(build(repo.path(), out.path(), REPO_URL).is_err());
}

#[test]
fn every_page_reads_offline_in_its_language() {
    let repo = site();
    let out = built(repo.path());
    let ru = read(out.path(), "ru/index.html");
    assert!(ru.contains(r#"<html lang="ru">"#), "{ru}");
    assert!(ru.contains("Документация"), "{ru}");
    assert!(ru.contains(r#"href="../style.css""#), "{ru}");
    assert!(out.path().join("style.css").is_file());
    for page in ["en/index.html", "en/quickstart.html", "ru/quickstart.html"] {
        let html = read(out.path(), page);
        assert!(!html.contains("<script"), "{page}");
        assert!(!html.contains(r#"src="http"#), "{page}");
    }
}
