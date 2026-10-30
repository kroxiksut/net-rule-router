//! The offline HTML of the user documentation: one page per Markdown file of
//! `docs/`, links between pages pointed at their HTML twins, pictures copied
//! beside them, one stylesheet, no script and nothing fetched off the disk.
//!
//! `docs/README.md` becomes `en/index.html` and `docs/README.<lang>.md`
//! `<lang>/index.html`; `docs/<lang>/<page>.md` becomes `<lang>/<page>.html`
//! and `docs/legal/<name>.<lang>.md` `<lang>/<name>.html`. A link to a file of
//! the repository outside `docs/` goes to the project online; one that reaches
//! nothing stops the build.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::Path;

use nrr_shared::docs_location::{DOCS_CANONICAL_LANGUAGE, DOCS_INDEX_PAGE};
use pulldown_cmark::{html, CowStr, Event, LinkType, Options, Parser, Tag, TagEnd};

const STYLE: &str = include_str!("style.css");
const STYLE_FILE: &str = "style.css";
/// Pictures of `docs/images/` the header shows: the Markdown keeps its own
/// copy of the logo for GitHub, which the offline body leaves out.
const IMAGES_DIR: &str = "images";
const LOGO_NAME: &str = "logo";
const LOCKUP_PREFIX: &str = "logo-lockup-";

#[derive(Debug)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn fail(message: impl Into<String>) -> Error {
    Error(message.into())
}

/// What one build wrote.
#[derive(Debug)]
pub struct Built {
    pub pages: usize,
    pub images: usize,
}

struct Page {
    /// Repository-relative, `/`-separated, as spelled on disk.
    source: String,
    /// Output-relative.
    output: String,
    language: String,
    text: String,
    ids: Vec<String>,
    anchors: HashSet<String>,
    title: String,
}

struct Site<'a> {
    repo: &'a Path,
    repo_url: &'a str,
    pages: Vec<Page>,
    by_source: HashMap<String, usize>,
    by_output: HashMap<String, usize>,
    lockups: HashMap<String, Lockup>,
}

/// The logo with the product name in one language, output-relative.
#[derive(Clone)]
struct Lockup {
    light: String,
    dark: Option<String>,
}

/// `docs/images/logo-lockup-<language>.png` and its `-dark` twin, if any.
fn lockup(repo: &Path, language: &str) -> Option<Lockup> {
    let file = |suffix: &str| {
        let output = format!("{IMAGES_DIR}/{LOCKUP_PREFIX}{language}{suffix}.png");
        join(repo, &format!("docs/{output}"))
            .is_file()
            .then_some(output)
    };
    Some(Lockup {
        light: file("")?,
        dark: file("-dark"),
    })
}

/// A repository path the page shows as its logo: the app icon or a lockup.
fn is_logo(joined: &str) -> bool {
    joined
        .strip_prefix("docs/")
        .and_then(|rest| rest.strip_prefix(IMAGES_DIR))
        .and_then(|rest| rest.strip_prefix('/'))
        .and_then(|name| name.strip_suffix(".png"))
        .is_some_and(|stem| stem == LOGO_NAME || stem.starts_with(LOCKUP_PREFIX))
}

/// Converts `<repo>/docs` into `out`, which must be absent or empty: a page
/// left from an earlier build would ship with links nobody checked.
pub fn build(repo: &Path, out: &Path, repo_url: &str) -> Result<Built, Error> {
    if fs::read_dir(out).is_ok_and(|mut entries| entries.next().is_some()) {
        return Err(fail(format!("{} is not empty", out.display())));
    }
    let mut pages = collect_pages(repo)?;
    for page in &mut pages {
        let outline = outline(&page.text);
        page.ids = outline.ids;
        page.anchors = outline.ids_set;
        page.title = outline
            .title
            .unwrap_or_else(|| page.output.trim_end_matches(".html").to_owned());
    }
    let by_source = pages
        .iter()
        .enumerate()
        .map(|(i, p)| (p.source.clone(), i))
        .collect();
    let by_output: HashMap<String, usize> = pages
        .iter()
        .enumerate()
        .map(|(i, p)| (p.output.clone(), i))
        .collect();
    if by_output.len() != pages.len() {
        return Err(fail("two Markdown files map to one HTML page"));
    }
    let english = lockup(repo, DOCS_CANONICAL_LANGUAGE);
    let lockups = pages
        .iter()
        .map(|p| p.language.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|language| {
            let found = lockup(repo, language).or_else(|| english.clone())?;
            Some((language.to_owned(), found))
        })
        .collect();
    let site = Site {
        repo,
        repo_url: repo_url.trim_end_matches('/'),
        pages,
        by_source,
        by_output,
        lockups,
    };
    if !site
        .by_output
        .contains_key(&index_of(DOCS_CANONICAL_LANGUAGE))
    {
        return Err(fail("docs/README.md is missing"));
    }

    let mut images = BTreeMap::new();
    for lockup in site.lockups.values() {
        for output in std::iter::once(&lockup.light).chain(&lockup.dark) {
            images.insert(output.clone(), format!("docs/{output}"));
        }
    }
    let mut rendered = Vec::with_capacity(site.pages.len());
    for at in 0..site.pages.len() {
        rendered.push(site.render(at, &mut images)?);
    }

    write_file(&out.join(STYLE_FILE), STYLE.as_bytes())?;
    for (page, html) in site.pages.iter().zip(&rendered) {
        write_file(&join(out, &page.output), html.as_bytes())?;
    }
    for (output, source) in &images {
        let bytes = fs::read(join(repo, source)).map_err(|e| fail(format!("{source}: {e}")))?;
        write_file(&join(out, output), &bytes)?;
    }
    Ok(Built {
        pages: rendered.len(),
        images: images.len(),
    })
}

fn index_of(language: &str) -> String {
    format!("{language}/{DOCS_INDEX_PAGE}")
}

fn join(root: &Path, relative: &str) -> std::path::PathBuf {
    relative
        .split('/')
        .fold(root.to_path_buf(), |path, part| path.join(part))
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| fail(format!("{}: {e}", parent.display())))?;
    }
    fs::write(path, bytes).map_err(|e| fail(format!("{}: {e}", path.display())))
}

fn is_language(id: &str) -> bool {
    !id.is_empty() && id.len() <= 8 && id.bytes().all(|b| b.is_ascii_lowercase())
}

fn read_page(repo: &Path, source: &str) -> Result<String, Error> {
    let text =
        fs::read_to_string(join(repo, source)).map_err(|e| fail(format!("{source}: {e}")))?;
    Ok(text.trim_start_matches('\u{feff}').to_owned())
}

fn file_names(dir: &Path) -> Result<Vec<(String, bool)>, Error> {
    let entries = fs::read_dir(dir).map_err(|e| fail(format!("{}: {e}", dir.display())))?;
    let mut names = Vec::new();
    for entry in entries.flatten() {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|name| fail(format!("{}: not UTF-8", name.to_string_lossy())))?;
        names.push((name, entry.path().is_dir()));
    }
    names.sort();
    Ok(names)
}

/// Every Markdown file of `docs/` with its output path; a Markdown file in a
/// place the layout does not know stops the build rather than going missing.
fn collect_pages(repo: &Path) -> Result<Vec<Page>, Error> {
    let docs = repo.join("docs");
    let mut found: Vec<(String, String, String)> = Vec::new();
    for (name, is_dir) in file_names(&docs)? {
        let source = format!("docs/{name}");
        if is_dir && name == "legal" {
            for (file, sub_dir) in file_names(&docs.join("legal"))? {
                let Some(stem) = file.strip_suffix(".md").filter(|_| !sub_dir) else {
                    continue;
                };
                let (base, language) = stem
                    .rsplit_once('.')
                    .filter(|(base, id)| !base.is_empty() && is_language(id))
                    .ok_or_else(|| fail(format!("docs/legal/{file}: no language suffix")))?;
                found.push((
                    format!("docs/legal/{file}"),
                    format!("{language}/{base}.html"),
                    language.to_owned(),
                ));
            }
        } else if is_dir && is_language(&name) {
            language_pages(&docs.join(&name), &source, &name, "", &mut found)?;
        } else if is_dir {
            if has_markdown(&docs.join(&name)) {
                return Err(fail(format!("{source}: not a language folder")));
            }
        } else if name == "README.md" {
            found.push((
                source,
                index_of(DOCS_CANONICAL_LANGUAGE),
                DOCS_CANONICAL_LANGUAGE.to_owned(),
            ));
        } else if let Some(language) = name
            .strip_prefix("README.")
            .and_then(|rest| rest.strip_suffix(".md"))
        {
            if !is_language(language) {
                return Err(fail(format!("{source}: unknown language")));
            }
            found.push((source, index_of(language), language.to_owned()));
        } else if name.ends_with(".md") {
            return Err(fail(format!(
                "{source}: no place in the offline documentation"
            )));
        }
    }
    found
        .into_iter()
        .map(|(source, output, language)| {
            Ok(Page {
                text: read_page(repo, &source)?,
                source,
                output,
                language,
                ids: Vec::new(),
                anchors: HashSet::new(),
                title: String::new(),
            })
        })
        .collect()
}

fn has_markdown(dir: &Path) -> bool {
    fs::read_dir(dir).is_ok_and(|entries| {
        entries.flatten().any(|e| {
            let path = e.path();
            if path.is_dir() {
                has_markdown(&path)
            } else {
                path.extension().is_some_and(|x| x == "md")
            }
        })
    })
}

fn language_pages(
    dir: &Path,
    source_dir: &str,
    language: &str,
    output_dir: &str,
    found: &mut Vec<(String, String, String)>,
) -> Result<(), Error> {
    for (name, is_dir) in file_names(dir)? {
        let source = format!("{source_dir}/{name}");
        if is_dir {
            language_pages(
                &dir.join(&name),
                &source,
                language,
                &format!("{output_dir}{name}/"),
                found,
            )?;
        } else if let Some(stem) = name.strip_suffix(".md") {
            found.push((
                source,
                format!("{language}/{output_dir}{stem}.html"),
                language.to_owned(),
            ));
        }
    }
    Ok(())
}

fn options() -> Options {
    Options::ENABLE_TABLES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_FOOTNOTES
        | Options::ENABLE_GFM
}

struct Outline {
    ids: Vec<String>,
    ids_set: HashSet<String>,
    title: Option<String>,
}

/// Heading ids in document order, numbered for repeats as GitHub numbers
/// them, and the first top-level heading as the title.
fn outline(text: &str) -> Outline {
    let mut ids = Vec::new();
    let mut ids_set = HashSet::new();
    let mut title = None;
    let mut heading: Option<(pulldown_cmark::HeadingLevel, String)> = None;
    for event in Parser::new_ext(text, options()) {
        match event {
            Event::Start(Tag::Heading { level, .. }) => heading = Some((level, String::new())),
            Event::Text(t) | Event::Code(t) => {
                if let Some((_, words)) = heading.as_mut() {
                    words.push_str(&t);
                }
            }
            Event::End(TagEnd::Heading(_)) => {
                let Some((level, words)) = heading.take() else {
                    continue;
                };
                if level == pulldown_cmark::HeadingLevel::H1 && title.is_none() {
                    title = Some(words.trim().to_owned());
                }
                let base = github_slug(&words);
                let mut id = base.clone();
                let mut repeat = 0;
                while ids_set.contains(&id) {
                    repeat += 1;
                    id = format!("{base}-{repeat}");
                }
                ids_set.insert(id.clone());
                ids.push(id);
            }
            _ => {}
        }
    }
    Outline {
        ids,
        ids_set,
        title,
    }
}

/// GitHub's heading anchor: rendered text lowercased, punctuation dropped,
/// each space a hyphen; letters of any script stay.
fn github_slug(text: &str) -> String {
    text.trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | ' '))
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
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

/// A repository path for a URL: every byte outside the unreserved set and
/// `/` percent-encoded.
fn percent_encoded(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `to` relative to the folder of `from`, both output-relative.
fn relative_url(from: &str, to: &str) -> String {
    let from_dir: Vec<&str> = from.split('/').collect();
    let from_dir = &from_dir[..from_dir.len() - 1];
    let to_parts: Vec<&str> = to.split('/').collect();
    let common = from_dir
        .iter()
        .zip(&to_parts)
        .take_while(|(a, b)| a == b)
        .count()
        .min(to_parts.len() - 1);
    let mut url = "../".repeat(from_dir.len() - common);
    url.push_str(&to_parts[common..].join("/"));
    url
}

/// Whether `parts` names an entry under `root` with exactly this spelling: a
/// case-insensitive disk would otherwise pass what GitHub and Linux refuse.
fn exists_as_spelled(root: &Path, parts: &[String]) -> Option<bool> {
    let mut current = root.to_path_buf();
    for part in parts {
        let entries = fs::read_dir(&current).ok()?;
        if !entries.flatten().any(|e| e.file_name() == part.as_str()) {
            return None;
        }
        current.push(part);
    }
    Some(current.is_dir())
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// What the language switch calls each language, in that language.
fn language_name(id: &str) -> String {
    match id {
        "en" => "English".to_owned(),
        "ru" => "Русский".to_owned(),
        other => other.to_ascii_uppercase(),
    }
}

impl Site<'_> {
    fn page_index(&self, language: &str) -> usize {
        self.by_output
            .get(&index_of(language))
            .or_else(|| self.by_output.get(&index_of(DOCS_CANONICAL_LANGUAGE)))
            .copied()
            .unwrap_or_default()
    }

    /// The repository path `path`, as written on page `at`, names.
    fn repo_parts(&self, at: usize, path: &str) -> Result<Vec<String>, String> {
        let mut parts: Vec<String> = if path.starts_with('/') {
            Vec::new()
        } else {
            let mut dir: Vec<String> = self.pages[at]
                .source
                .split('/')
                .map(str::to_owned)
                .collect();
            dir.pop();
            dir
        };
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    if parts.pop().is_none() {
                        return Err("outside the repository".to_owned());
                    }
                }
                part => parts.push(part.to_owned()),
            }
        }
        Ok(parts)
    }

    /// The repository file a link of page `at` names, if it names one.
    fn target_file(&self, at: usize, target: &str) -> Option<String> {
        if is_external(target) {
            return None;
        }
        let path = percent_decoded(target.split(['#', '?']).next().unwrap_or_default());
        if path.is_empty() {
            return None;
        }
        self.repo_parts(at, &path).ok().map(|parts| parts.join("/"))
    }

    /// Whether a link of page `at` opens the same page in another language.
    fn is_twin(&self, at: usize, target: &str) -> bool {
        let page = &self.pages[at];
        let rest = |p: &Page| p.output.split_once('/').map(|(_, rest)| rest.to_owned());
        self.target_file(at, target)
            .and_then(|joined| self.by_source.get(&joined))
            .map(|&found| &self.pages[found])
            .is_some_and(|twin| twin.language != page.language && rest(twin) == rest(page))
    }

    /// Whether a paragraph of page `at` is one the header already shows: the
    /// language switch (links to this page's twins, the current language in
    /// bold, separators between) or the logo picture alone.
    fn shown_in_header(&self, at: usize, inner: &[Event]) -> bool {
        let (mut links, mut logos, mut nested) = (0usize, 0usize, 0usize);
        for event in inner {
            match event {
                Event::Start(Tag::Link { dest_url, .. }) if self.is_twin(at, dest_url) => {
                    links += 1;
                    nested += 1;
                }
                Event::Start(Tag::Image { dest_url, .. })
                    if self.target_file(at, dest_url).is_some_and(|f| is_logo(&f)) =>
                {
                    logos += 1;
                    nested += 1;
                }
                Event::Start(Tag::Strong | Tag::Emphasis) => nested += 1,
                Event::End(TagEnd::Link | TagEnd::Image | TagEnd::Strong | TagEnd::Emphasis) => {
                    nested = nested.saturating_sub(1);
                }
                Event::Text(text) if nested > 0 || !text.chars().any(char::is_alphanumeric) => {}
                Event::SoftBreak => {}
                _ => return false,
            }
        }
        (links, logos) == (0, 1) || (links > 0 && logos == 0)
    }

    /// Which events of a page fall in a top-level paragraph `shown_in_header`.
    fn header_duplicates(&self, at: usize, events: &[Event]) -> Vec<bool> {
        let mut skip = vec![false; events.len()];
        let mut depth = 0usize;
        let mut i = 0;
        while i < events.len() {
            match &events[i] {
                Event::Start(Tag::Paragraph) if depth == 0 => {
                    let Some(end) = events[i..]
                        .iter()
                        .position(|e| matches!(e, Event::End(TagEnd::Paragraph)))
                        .map(|n| i + n)
                    else {
                        break;
                    };
                    if self.shown_in_header(at, &events[i + 1..end]) {
                        skip[i..=end].fill(true);
                    }
                    i = end;
                }
                Event::Start(_) => depth += 1,
                Event::End(_) => depth = depth.saturating_sub(1),
                _ => {}
            }
            i += 1;
        }
        skip
    }

    /// The URL a link of page `at` gets, or why it reaches nothing.
    fn resolve(
        &self,
        at: usize,
        target: &str,
        images: &mut BTreeMap<String, String>,
    ) -> Result<String, String> {
        let page = &self.pages[at];
        if target.is_empty() {
            return Err("empty link".to_owned());
        }
        if is_external(target) {
            return Ok(target.to_owned());
        }
        let (path, fragment) = target.split_once('#').unwrap_or((target, ""));
        let path = percent_decoded(path.split('?').next().unwrap_or_default());
        if path.is_empty() {
            return if page.anchors.contains(&percent_decoded(fragment)) {
                Ok(format!("#{fragment}"))
            } else {
                Err("no such heading".to_owned())
            };
        }
        let parts = self.repo_parts(at, &path)?;
        let joined = parts.join("/");
        let with_fragment = |url: String| {
            if fragment.is_empty() {
                url
            } else {
                format!("{url}#{fragment}")
            }
        };

        let twin = self.by_source.get(&joined).copied().or_else(|| {
            // A page not translated yet is read in English.
            let rest = joined.strip_prefix("docs/")?.split_once('/')?.1;
            let english = format!("docs/{DOCS_CANONICAL_LANGUAGE}/{rest}");
            (english != joined)
                .then(|| self.by_source.get(&english).copied())
                .flatten()
                .filter(|_| exists_as_spelled(self.repo, &parts).is_none())
        });
        if let Some(target_page) = twin {
            let found = &self.pages[target_page];
            let url = relative_url(&page.output, &found.output);
            let translated = found.source == joined;
            return match (
                fragment.is_empty(),
                found.anchors.contains(&percent_decoded(fragment)),
            ) {
                (true, _) | (false, true) => Ok(with_fragment(url)),
                // A heading of the missing translation: the English page itself.
                (false, false) if !translated => Ok(url),
                (false, false) => Err("no such heading".to_owned()),
            };
        }
        match exists_as_spelled(self.repo, &parts) {
            None => Err("no such file".to_owned()),
            Some(false) if joined.starts_with("docs/") => {
                let output = joined["docs/".len()..].to_owned();
                let url = relative_url(&page.output, &output);
                images.insert(output, joined);
                Ok(with_fragment(url))
            }
            Some(is_dir) => {
                let kind = if is_dir { "tree" } else { "blob" };
                let slash = if is_dir && path.ends_with('/') {
                    "/"
                } else {
                    ""
                };
                Ok(with_fragment(format!(
                    "{}/{kind}/main/{}{slash}",
                    self.repo_url,
                    percent_encoded(&joined)
                )))
            }
        }
    }

    fn render(&self, at: usize, images: &mut BTreeMap<String, String>) -> Result<String, Error> {
        let page = &self.pages[at];
        let broken = |target: &str, reason: &str| {
            fail(format!(
                "{}: link {target} reaches nothing ({reason})",
                page.source
            ))
        };
        let mut ids = page.ids.iter();
        let source: Vec<Event> = Parser::new_ext(&page.text, options()).collect();
        let skip = self.header_duplicates(at, &source);
        let mut events = Vec::with_capacity(source.len());
        for (event, skipped) in source.into_iter().zip(skip) {
            if skipped {
                continue;
            }
            let event = match event {
                Event::Start(Tag::Heading {
                    level,
                    classes,
                    attrs,
                    ..
                }) => Event::Start(Tag::Heading {
                    level,
                    id: ids.next().map(|id| CowStr::from(id.as_str())),
                    classes,
                    attrs,
                }),
                Event::Start(Tag::Link {
                    link_type,
                    dest_url,
                    title,
                    id,
                }) if !matches!(link_type, LinkType::Email | LinkType::Autolink) => {
                    let url = self
                        .resolve(at, &dest_url, images)
                        .map_err(|reason| broken(&dest_url, &reason))?;
                    Event::Start(Tag::Link {
                        link_type,
                        dest_url: url.into(),
                        title,
                        id,
                    })
                }
                Event::Start(Tag::Image {
                    link_type,
                    dest_url,
                    title,
                    id,
                }) => {
                    let url = self
                        .resolve(at, &dest_url, images)
                        .map_err(|reason| broken(&dest_url, &reason))?;
                    Event::Start(Tag::Image {
                        link_type,
                        dest_url: url.into(),
                        title,
                        id,
                    })
                }
                Event::Html(raw) | Event::InlineHtml(raw)
                    if ["href", "src"]
                        .iter()
                        .any(|a| raw.to_ascii_lowercase().contains(a)) =>
                {
                    return Err(fail(format!(
                        "{}: a link inside raw HTML is not rewritten: {}",
                        page.source,
                        raw.trim()
                    )));
                }
                other => other,
            };
            events.push(event);
        }
        let mut body = String::with_capacity(page.text.len() * 2);
        html::push_html(&mut body, events.into_iter());
        Ok(self.wrap(at, &body))
    }

    fn wrap(&self, at: usize, body: &str) -> String {
        let page = &self.pages[at];
        let home = &self.pages[self.page_index(&page.language)];
        let languages: BTreeSet<&str> = self.pages.iter().map(|p| p.language.as_str()).collect();
        let rest = page.output.split_once('/').map_or("", |(_, rest)| rest);
        let mut switch = String::new();
        for language in languages.iter().filter(|l| **l != page.language) {
            let twin = format!("{language}/{rest}");
            let target = if self.by_output.contains_key(&twin) {
                twin
            } else {
                self.pages[self.page_index(language)].output.clone()
            };
            switch.push_str(&format!(
                "<a href=\"{}\" lang=\"{language}\" hreflang=\"{language}\">{}</a>",
                relative_url(&page.output, &target),
                escape(&language_name(language)),
            ));
        }
        format!(
            "<!doctype html>\n<html lang=\"{lang}\">\n<head>\n<meta charset=\"utf-8\">\n\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
             <meta name=\"color-scheme\" content=\"light dark\">\n<title>{title}</title>\n\
             <link rel=\"stylesheet\" href=\"{style}\">\n</head>\n<body>\n\
             <header class=\"site\"><a class=\"home\" href=\"{home_url}\">{home_label}</a>\
             <nav class=\"languages\">{switch}</nav></header>\n\
             <main>\n{body}</main>\n</body>\n</html>\n",
            lang = page.language,
            title = escape(&page.title),
            style = relative_url(&page.output, STYLE_FILE),
            home_url = relative_url(&page.output, &home.output),
            home_label = self.home_label(at, &escape(&home.title)),
        )
    }

    /// The header's way home: the logo in the page's language, with a version
    /// for a dark page when there is one, or else the home page's title.
    fn home_label(&self, at: usize, title: &str) -> String {
        let page = &self.pages[at];
        let Some(lockup) = self.lockups.get(&page.language) else {
            return title.to_owned();
        };
        let dark = lockup.dark.as_ref().map_or(String::new(), |dark| {
            format!(
                "<source media=\"(prefers-color-scheme: dark)\" srcset=\"{}\">",
                relative_url(&page.output, dark)
            )
        });
        format!(
            "<picture>{dark}<img class=\"lockup\" src=\"{}\" alt=\"{title}\"></picture>",
            relative_url(&page.output, &lockup.light)
        )
    }
}
