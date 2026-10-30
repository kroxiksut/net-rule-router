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

fn header(html: &str) -> &str {
    &html[html.find("<header").expect("header")..html.find("</header>").expect("end")]
}

fn body(html: &str) -> &str {
    &html[html.find("<main>").expect("main")..html.find("</main>").expect("end")]
}

fn write_lockups(root: &Path, languages: &[&str]) {
    for language in languages {
        for suffix in ["", "-dark"] {
            let name = format!("docs/images/logo-lockup-{language}{suffix}.png");
            write(root, &name, &name);
        }
    }
}

/// Every page, the nested ones too, opens with the logo in its own language,
/// readable on a dark page as well, leading home.
#[test]
fn every_page_header_shows_the_logo_of_its_language_leading_home() {
    let repo = site();
    write_lockups(repo.path(), &["en", "ru"]);
    let out = built(repo.path());
    for (page, language, title) in [
        ("en/index.html", "en", "Docs"),
        ("en/quickstart.html", "en", "Docs"),
        ("ru/quickstart.html", "ru", "Документация"),
    ] {
        let html = read(out.path(), page);
        let header = header(&html);
        for expected in [
            format!(r#"src="../images/logo-lockup-{language}.png""#),
            format!(
                r#"<source media="(prefers-color-scheme: dark)" srcset="../images/logo-lockup-{language}-dark.png">"#
            ),
            format!(r#"alt="{title}""#),
            r#"href="index.html""#.to_owned(),
        ] {
            assert!(header.contains(&expected), "{page}: {expected} in {header}");
        }
    }
    for language in ["en", "ru"] {
        for suffix in ["", "-dark"] {
            let name = format!("images/logo-lockup-{language}{suffix}.png");
            assert_eq!(read(out.path(), &name), format!("docs/{name}"));
        }
    }
}

#[test]
fn a_language_without_its_own_logo_shows_the_english_one() {
    let repo = site();
    write_lockups(repo.path(), &["en"]);
    let out = built(repo.path());
    let html = read(out.path(), "ru/quickstart.html");
    let header = header(&html);
    assert!(
        header.contains(r#"src="../images/logo-lockup-en.png""#)
            && header.contains(r#"srcset="../images/logo-lockup-en-dark.png""#)
            && header.contains(r#"alt="Документация""#),
        "{header}"
    );
}

/// The language switch and the logo the Markdown carries for GitHub are in
/// the header already; the page body does not show them a second time.
#[test]
fn the_body_does_not_repeat_the_language_switch_or_the_logo() {
    let repo = site();
    write_lockups(repo.path(), &["en", "ru"]);
    write(
        repo.path(),
        "docs/en/quickstart.md",
        "# Quick start\n\n**English** · [Русский](../ru/quickstart.md)\n\n\
         ![NetRuleRouter](../images/logo-lockup-en.png)\n\n## First steps\n\n\
         ![Rules](images/rules.png)\n\nRead it [in Russian](../ru/quickstart.md) too.\n\n\
         [Priority](priority.md#zones)\n",
    );
    write(
        repo.path(),
        "docs/ru/quickstart.md",
        "# Быстрый старт\n\n[English](../en/quickstart.md) | **Русский**\n\n\
         ![NetRuleRouter](../images/logo.png)\n\n[Приоритет](priority.md)\n",
    );
    write(repo.path(), "docs/images/logo.png", "logo");
    let out = built(repo.path());
    for (page, twin) in [
        ("en/index.html", "../ru/index.html"),
        ("ru/index.html", "../en/index.html"),
        ("en/quickstart.html", "../ru/quickstart.html"),
        ("ru/quickstart.html", "../en/quickstart.html"),
    ] {
        let html = read(out.path(), page);
        let main = body(&html);
        assert!(!main.contains("logo"), "{page}: {main}");
        let switch = format!(r#"href="{twin}""#);
        assert!(header(&html).contains(&switch), "{page}: {html}");
        if page == "en/quickstart.html" {
            // A sentence that only mentions the twin is not the switch.
            assert!(
                main.contains("in Russian") && main.contains(&switch),
                "{main}"
            );
            assert!(main.contains(r#"src="images/rules.png""#), "{main}");
        } else {
            assert!(!main.contains(&switch), "{page}: {main}");
        }
    }
    assert!(!out.path().join("images/logo.png").exists());
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
