#![allow(clippy::expect_used)]

//! A relative link or image in the published documentation reaches a file
//! that exists as spelled, and a `#fragment` reaches a heading of the page it
//! names. GitHub and case-sensitive file systems show anything less as a 404.
//! External links are not fetched.

use std::collections::{HashMap, HashSet};
use std::path::Path;

const ROOT_PAGES: &[&str] = &[
    "README.md",
    "README_RU.md",
    "ROADMAP.md",
    "ROADMAP_RU.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
];

fn markdown_files(dir: &Path, relative: &str, found: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        let child = format!("{relative}/{name}");
        if path.is_dir() {
            markdown_files(&path, &child, found);
        } else if name.ends_with(".md") {
            found.push(child);
        }
    }
}

/// Lines outside fenced code blocks, numbered from 1.
fn prose_lines(text: &str) -> Vec<(usize, &str)> {
    let mut fence: Option<(char, usize)> = None;
    let mut prose = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        let marker = trimmed.chars().next().filter(|c| *c == '`' || *c == '~');
        let run = marker.map_or(0, |m| trimmed.chars().take_while(|c| *c == m).count());
        match (fence, marker) {
            (None, Some(m)) if run >= 3 => fence = Some((m, run)),
            (Some((open, len)), Some(m))
                if m == open && run >= len && trimmed[run..].trim().is_empty() =>
            {
                fence = None
            }
            (None, _) => prose.push((index + 1, line)),
            _ => {}
        }
    }
    prose
}

/// The line with code spans blanked; an unmatched backtick run stays literal.
fn without_code_spans(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'`' {
            let next = line[i..].find('`').map_or(line.len(), |n| i + n);
            out.push_str(&line[i..next]);
            i = next;
            continue;
        }
        let run = bytes[i..].iter().take_while(|b| **b == b'`').count();
        let mut close = None;
        let mut j = i + run;
        while j < bytes.len() {
            if bytes[j] == b'`' {
                let len = bytes[j..].iter().take_while(|b| **b == b'`').count();
                if len == run {
                    close = Some(j + len);
                    break;
                }
                j += len;
            } else {
                j += 1;
            }
        }
        match close {
            Some(end) => {
                out.push(' ');
                i = end;
            }
            None => {
                out.push_str(&line[i..i + run]);
                i += run;
            }
        }
    }
    out
}

/// A link destination at the start of `rest`: `<...>`, or up to whitespace
/// or the `)` that closes it, parentheses balanced.
fn destination(rest: &str) -> &str {
    if let Some(inner) = rest.strip_prefix('<') {
        return inner.find('>').map_or("", |end| &inner[..end]);
    }
    let mut depth = 0usize;
    for (at, c) in rest.char_indices() {
        match c {
            '(' => depth += 1,
            ')' if depth == 0 => return &rest[..at],
            ')' => depth -= 1,
            c if c.is_whitespace() => return &rest[..at],
            _ => {}
        }
    }
    rest
}

/// Inline links and images, `[label]: target` definitions and HTML
/// `src`/`href` attributes of one prose line.
fn link_targets(line: &str) -> Vec<String> {
    let line = without_code_spans(line);
    let mut targets = Vec::new();
    let mut rest = line.as_str();
    while let Some(at) = rest.find("](") {
        rest = &rest[at + 2..];
        targets.push(destination(rest).to_owned());
    }
    for attribute in [" src=", " href="] {
        let mut rest = line.as_str();
        while let Some(at) = rest.find(attribute) {
            rest = &rest[at + attribute.len()..];
            let Some(quote) = rest.chars().next().filter(|c| *c == '"' || *c == '\'') else {
                continue;
            };
            if let Some(end) = rest[1..].find(quote) {
                targets.push(rest[1..1 + end].to_owned());
            }
        }
    }
    let definition = line.trim_start();
    if definition.starts_with('[') && !definition.starts_with("[^") {
        if let Some(end) = definition
            .find("]:")
            .filter(|end| !definition[1..*end].contains(']'))
        {
            targets.push(destination(definition[end + 2..].trim_start()).to_owned());
        }
    }
    targets
}

fn is_external(target: &str) -> bool {
    if target.starts_with("//") {
        return true;
    }
    let scheme = target.split(':').next().unwrap_or_default();
    scheme.len() < target.len()
        && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

fn percent_decoded(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (bytes[i], hex) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// GitHub's heading anchor: rendered text lowercased, punctuation dropped,
/// each space a hyphen; letters of any script stay.
fn heading_slug(heading: &str) -> String {
    let mut text = String::new();
    let mut rest = heading;
    while let Some(at) = rest.find("](") {
        text.push_str(&rest[..at]);
        let tail = &rest[at + 2..];
        let skip = destination(tail).len();
        rest = tail[skip..].split_once(')').map_or("", |(_, after)| after);
    }
    text.push_str(rest);
    text.to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | ' '))
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

/// Anchors of a page's ATX headings, repeats numbered as GitHub numbers them.
fn heading_anchors(text: &str) -> HashSet<String> {
    let mut anchors = HashSet::new();
    for (_, line) in prose_lines(text) {
        let trimmed = line.trim_start();
        let level = trimmed.chars().take_while(|c| *c == '#').count();
        let body = &trimmed[level..];
        if line.len() - trimmed.len() > 3
            || !(1..=6).contains(&level)
            || !(body.is_empty() || body.starts_with(' '))
        {
            continue;
        }
        let body = body.trim();
        let body = match body.trim_end_matches('#') {
            closed if closed.len() < body.len() && (closed.is_empty() || closed.ends_with(' ')) => {
                closed.trim_end()
            }
            _ => body,
        };
        let base = heading_slug(body);
        let mut anchor = base.clone();
        let mut repeat = 0;
        while anchors.contains(&anchor) {
            repeat += 1;
            anchor = format!("{base}-{repeat}");
        }
        anchors.insert(anchor);
    }
    anchors
}

/// Whether `parts` names an entry under `root` with exactly this spelling:
/// a case-insensitive disk would otherwise pass what GitHub refuses.
fn exists_as_spelled(root: &Path, parts: &[String]) -> bool {
    let mut current = root.to_path_buf();
    for part in parts {
        let Ok(entries) = std::fs::read_dir(&current) else {
            return false;
        };
        if !entries.flatten().any(|e| e.file_name() == part.as_str()) {
            return false;
        }
        current.push(part);
    }
    true
}

/// `page:line: target (reason)` for every relative link of `pages` (paths
/// under `root`, `/`-separated) that does not resolve.
fn broken_links(root: &Path, pages: &[String]) -> Vec<String> {
    let mut anchors: HashMap<Vec<String>, HashSet<String>> = HashMap::new();
    let mut broken = Vec::new();
    for page in pages {
        let text = std::fs::read_to_string(root.join(page)).expect("read page");
        let page_parts: Vec<String> = page.split('/').map(str::to_owned).collect();
        for (number, line) in prose_lines(&text) {
            for target in link_targets(line) {
                if is_external(&target) {
                    continue;
                }
                let (path, fragment) = target.split_once('#').unwrap_or((target.as_str(), ""));
                let path = percent_decoded(path.split('?').next().unwrap_or_default());
                let reason = if target.is_empty() {
                    Some("empty link")
                } else if path.is_empty() {
                    resolve_fragment(root, &page_parts, fragment, &mut anchors)
                } else {
                    let mut parts: Vec<String> = if path.starts_with('/') {
                        Vec::new()
                    } else {
                        page_parts[..page_parts.len() - 1].to_vec()
                    };
                    let mut outside = false;
                    for part in path.split('/') {
                        match part {
                            "" | "." => {}
                            ".." => outside |= parts.pop().is_none(),
                            part => parts.push(part.to_owned()),
                        }
                    }
                    if outside {
                        Some("outside the repository")
                    } else if !exists_as_spelled(root, &parts) {
                        Some("no such file")
                    } else {
                        resolve_fragment(root, &parts, fragment, &mut anchors)
                    }
                };
                if let Some(reason) = reason {
                    broken.push(format!("{page}:{number}: {target} ({reason})"));
                }
            }
        }
    }
    broken
}

/// A fragment is checked only on a Markdown page: GitHub numbers source
/// lines (`#L10`) and folders have no headings.
fn resolve_fragment(
    root: &Path,
    parts: &[String],
    fragment: &str,
    anchors: &mut HashMap<Vec<String>, HashSet<String>>,
) -> Option<&'static str> {
    let is_page = parts.last().is_some_and(|name| name.ends_with(".md"));
    if fragment.is_empty() || !is_page {
        return None;
    }
    let known = anchors.entry(parts.to_vec()).or_insert_with(|| {
        let text = std::fs::read_to_string(root.join(parts.join("/"))).unwrap_or_default();
        heading_anchors(&text)
    });
    (!known.contains(&percent_decoded(fragment))).then_some("no such heading")
}

#[test]
fn every_published_link_resolves() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut pages: Vec<String> = ROOT_PAGES.iter().map(|p| (*p).to_owned()).collect();
    let mut docs = Vec::new();
    markdown_files(&root.join("docs"), "docs", &mut docs);
    docs.sort();
    assert!(!docs.is_empty(), "{}", root.display());
    pages.extend(docs);
    assert_eq!(
        broken_links(&root, &pages),
        Vec::<String>::new(),
        "a reader following these links gets a 404"
    );
}

/// Every kind of broken link is reported with its page and line; what is
/// fine, external or inside code is not.
#[test]
fn a_broken_link_image_or_heading_is_reported() {
    let root = tempfile::tempdir().expect("tempdir");
    let write = |relative: &str, text: &str| {
        let path = root.path().join(relative);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
        std::fs::write(path, text).expect("write");
    };
    write(
        "README.md",
        "# Title\n\
         [ok](docs/en/page.md) and [ok](<docs/en/my page.md> \"title\") and [ok](docs/en/my%20page.md)\n\
         [heading](docs/en/page.md#второй-раздел) [twice](docs/en/page.md#notes-1) [styled](docs/en/page.md#code-and-bold-done)\n\
         ![missing image](docs/en/images/missing.png)\n\
         [missing page](docs/en/gone.md)\n\
         [wrong case](Docs/en/page.md)\n\
         [bad heading](docs/en/page.md#no-such-heading)\n\
         [escapes](../outside.md)\n\
         [web](https://example.invalid/a_(b).md) [mail](mailto:someone@example.invalid) [source](core/lib.rs#L10)\n\
         `[in code](nowhere.md)` and ``[in ``code``](nowhere.md)``\n\
         ```text\n\
         [in fence](nowhere.md)\n\
         ```\n\
         <img src=\"docs/en/images/shot.png\" alt=\"ok\"> <img src=\"docs/en/images/absent.png\" alt=\"gone\">\n\
         [self](#title) [self](#nope) [folder](docs/en/)\n\
         [ref]: docs/en/absent-ref.md\n",
    );
    write(
        "docs/en/page.md",
        "# Page\n\n## Второй раздел\n\n## Notes\n\n## Notes ##\n\n## `code` and **bold**: done!\n\n[up](../../README.md#title) [up](../../README.md#Title)\n",
    );
    write("docs/en/my page.md", "# Spaces\n");
    write("docs/en/images/shot.png", "");
    write("core/lib.rs", "");

    let pages = [
        "README.md".to_owned(),
        "docs/en/page.md".to_owned(),
        "docs/en/my page.md".to_owned(),
    ];
    assert_eq!(
        broken_links(root.path(), &pages),
        [
            "README.md:4: docs/en/images/missing.png (no such file)",
            "README.md:5: docs/en/gone.md (no such file)",
            "README.md:6: Docs/en/page.md (no such file)",
            "README.md:7: docs/en/page.md#no-such-heading (no such heading)",
            "README.md:8: ../outside.md (outside the repository)",
            "README.md:14: docs/en/images/absent.png (no such file)",
            "README.md:15: #nope (no such heading)",
            "README.md:16: docs/en/absent-ref.md (no such file)",
            "docs/en/page.md:11: ../../README.md#Title (no such heading)",
        ]
    );
}
