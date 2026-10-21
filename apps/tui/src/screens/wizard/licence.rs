//! The licence gate: the agreement the window shows before first use, here a
//! few paragraphs at a time so a small terminal never clips it.

/// Embedded like the window's copy, so the text is there however the binary
/// is deployed.
const EULA_RU: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/legal/eula.ru.md"
));
const EULA_EN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/legal/eula.en.md"
));

/// About three quarters of a screen of a narrow terminal.
const PAGE_CHARS: usize = 700;

/// The agreement for a session language: Russian for `ru`, English otherwise,
/// as the window picks.
pub fn text(language: &str) -> &'static str {
    if language
        .split(['-', '_'])
        .next()
        .is_some_and(|base| base.eq_ignore_ascii_case("ru"))
    {
        EULA_RU
    } else {
        EULA_EN
    }
}

/// The text in pages of paragraphs, none much over [`PAGE_CHARS`] unless one
/// paragraph is longer on its own. Blank lines between paragraphs are kept
/// inside a page and dropped at its edges.
pub fn pages(text: &str) -> Vec<Vec<String>> {
    // A Windows checkout embeds the files with CRLF.
    let text = text.replace("\r\n", "\n");
    let mut pages: Vec<Vec<String>> = Vec::new();
    let mut page: Vec<String> = Vec::new();
    let mut size = 0usize;
    for paragraph in text.split("\n\n") {
        let lines: Vec<String> = paragraph
            .trim_matches('\n')
            .lines()
            .map(|line| line.trim_end().to_string())
            .collect();
        let chars: usize = lines.iter().map(|l| l.chars().count() + 1).sum();
        if lines.is_empty() {
            continue;
        }
        if size > 0 && size + chars > PAGE_CHARS {
            pages.push(std::mem::take(&mut page));
            size = 0;
        }
        if !page.is_empty() {
            page.push(String::new());
        }
        page.extend(lines);
        size += chars;
    }
    if !page.is_empty() {
        pages.push(page);
    }
    pages
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_session_language_picks_the_agreement() {
        assert!(text("ru").chars().any(|c| ('а'..='я').contains(&c)));
        assert_eq!(text("ru-RU"), text("ru"));
        assert_eq!(text("en"), text("de"));
        assert_ne!(text("ru"), text("en"));
    }

    #[test]
    fn pages_hold_every_paragraph_once_and_in_order() {
        for language in ["ru", "en"] {
            let whole = text(language);
            let pages = pages(whole);
            assert!(pages.len() > 1, "{language}: a real agreement spans pages");
            let rejoined: Vec<&str> = pages
                .iter()
                .flatten()
                .map(String::as_str)
                .filter(|l| !l.is_empty())
                .collect();
            let original: Vec<&str> = whole
                .lines()
                .map(str::trim_end)
                .filter(|l| !l.is_empty())
                .collect();
            assert_eq!(rejoined, original, "{language}");
        }
    }

    #[test]
    fn a_page_neither_starts_nor_ends_with_a_blank_line() {
        for page in pages(text("en")) {
            assert_ne!(page.first().map(String::as_str), Some(""));
            assert_ne!(page.last().map(String::as_str), Some(""));
        }
    }

    #[test]
    fn a_long_paragraph_is_one_page_not_cut() {
        let long = "word ".repeat(400);
        let pages = pages(&format!("short\n\n{long}\n\ntail"));
        assert_eq!(pages.len(), 3);
        assert_eq!(pages[1].len(), 1);
    }

    #[test]
    fn empty_text_has_no_pages() {
        assert!(pages("").is_empty());
        assert!(pages("\n\n\n").is_empty());
    }
}
