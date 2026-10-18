//! Names the OS or a remote party shaped, made safe to put on a screen.
//!
//! A program name, an exe path, an adapter name, a registry `DisplayName` or a
//! PTR name is written by someone else. A terminal executes its control
//! characters; bidi controls make `gnp\u{202E}.exe` read as `exe.png`; an
//! invisible character makes two different names look the same. Each such
//! character is replaced by a visible `·`, so a forgery stays visible instead of
//! being silently repaired.
//!
//! DISPLAY ONLY. A host name or a path that builds or matches a rule is a key:
//! a "repaired" key names another object, so keys never pass through here.
//!
//! The GUI twin is `displayText` in `apps/desktop/qml/lib/pure.js`, held to
//! this one by `core/client-logic/tests/vectors/display_text.json`.

use std::borrow::Cow;

/// What stands in for every character [`needs_substitute`] flags.
pub const SUBSTITUTE: char = '\u{00B7}';

/// What marks the cut of a name longer than [`DISPLAY_MAX_CHARS`].
pub const ELLIPSIS: char = '\u{2026}';

/// The longest shown name, in code points. Above MAX_PATH (260) and a DNS
/// name (253), so a real name is never cut, yet a hostile megabyte-long name
/// costs a bounded layout on every repaint.
pub const DISPLAY_MAX_CHARS: usize = 512;

/// The cut keeps both ends: a path's file name sits at its end, its folder at
/// its start, and either alone can impersonate.
const HEAD_CHARS: usize = 255;
const TAIL_CHARS: usize = DISPLAY_MAX_CHARS - HEAD_CHARS - 1;

/// Whether `c` executes, reorders or hides text instead of showing itself.
///
/// Beyond the controls, bidi controls and zero-width characters, this takes
/// every format character that is invisible or can hide text. Left alone:
/// format characters that draw a visible sign (Arabic number signs U+0600–0605,
/// end of ayah, Kaithi number signs), Egyptian hieroglyph layout controls,
/// Mongolian variation selectors and U+FE00–FE0F, which pick emoji or text
/// presentation in ordinary names and hide nothing.
#[must_use]
pub fn needs_substitute(c: char) -> bool {
    matches!(
        c,
        // C0, DEL and C1 (8-bit CSI U+009B, NEL U+0085): a terminal executes them.
        '\u{0}'..='\u{1F}'
            | '\u{7F}'..='\u{9F}'
            // Bidi marks, embeddings, overrides and isolates.
            | '\u{061C}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            // Zero-width and invisible: two names differing only here look alike.
            | '\u{00AD}'
            | '\u{034F}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200D}'
            | '\u{2060}'..='\u{2064}'
            | '\u{206A}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            // Letters that draw nothing: a name of them looks empty.
            | '\u{115F}'
            | '\u{1160}'
            | '\u{3164}'
            | '\u{FFA0}'
            // Line and paragraph separators break a one-line name.
            | '\u{2028}'
            | '\u{2029}'
            // Interlinear annotation: a renderer may hide the annotated text.
            | '\u{FFF9}'..='\u{FFFB}'
            // Tags and supplementary variation selectors: invisible, and a run
            // of them carries a hidden payload.
            | '\u{E0000}'..='\u{E007F}'
            | '\u{E0100}'..='\u{E01EF}'
    )
}

/// `raw` as a screen may show it: every [`needs_substitute`] character turned
/// into [`SUBSTITUTE`], and a name above [`DISPLAY_MAX_CHARS`] cut in the middle
/// with [`ELLIPSIS`]. Borrows when nothing changes; reads at most a cap's worth
/// from each end, however long `raw` is.
#[must_use]
pub fn display_text(raw: &str) -> Cow<'_, str> {
    if raw.char_indices().nth(DISPLAY_MAX_CHARS).is_none() {
        return if raw.chars().any(needs_substitute) {
            let mut out = String::with_capacity(raw.len());
            push_substituted(&mut out, raw);
            Cow::Owned(out)
        } else {
            Cow::Borrowed(raw)
        };
    }
    // More than DISPLAY_MAX_CHARS code points, so the head ends before the tail.
    let head_end = raw
        .char_indices()
        .nth(HEAD_CHARS)
        .map_or(raw.len(), |(at, _)| at);
    let tail_start = raw
        .char_indices()
        .rev()
        .nth(TAIL_CHARS - 1)
        .map_or(0, |(at, _)| at);
    let (head, tail) = (&raw[..head_end], &raw[tail_start..]);
    let mut out = String::with_capacity(head.len() + ELLIPSIS.len_utf8() + tail.len());
    push_substituted(&mut out, head);
    out.push(ELLIPSIS);
    push_substituted(&mut out, tail);
    Cow::Owned(out)
}

fn push_substituted(out: &mut String, text: &str) {
    for c in text.chars() {
        out.push(if needs_substitute(c) { SUBSTITUTE } else { c });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_name_is_borrowed_unchanged() {
        for name in [
            "",
            "app.exe",
            r"C:\Program Files\Example\example.exe",
            "Программа.exe",
            "程序.exe",
            "برنامج.exe",
            "e\u{0301}",
            "\u{2764}\u{FE0F}",
            "a b\u{00A0}c",
        ] {
            assert!(
                matches!(display_text(name), Cow::Borrowed(s) if s == name),
                "{name:?}"
            );
        }
    }

    #[test]
    fn controls_turn_into_a_visible_dot() {
        assert_eq!(display_text("\u{1B}]52;c;aGk=\u{7}"), "·]52;c;aGk=·");
        assert_eq!(display_text("a\tb\nc\r\0"), "a·b·c··");
        assert_eq!(display_text("x\u{7F}\u{9B}\u{85}"), "x···");
    }

    #[test]
    fn bidi_controls_cannot_reverse_an_extension() {
        assert_eq!(display_text("gnp\u{202E}.exe"), "gnp·.exe");
        assert_eq!(display_text("\u{2066}a\u{2069}\u{200F}"), "·a··");
        assert_eq!(display_text("\u{061C}x\u{202A}"), "·x·");
    }

    #[test]
    fn invisible_characters_become_visible() {
        assert_eq!(display_text("exa\u{200B}mple"), "exa·mple");
        assert_eq!(display_text("\u{FEFF}name\u{2060}"), "·name·");
        assert_eq!(display_text("soft\u{00AD}hyphen"), "soft·hyphen");
        assert_eq!(display_text("\u{3164}"), "·");
        assert_eq!(display_text("t\u{E0041}\u{E0100}"), "t··");
        assert_eq!(display_text("a\u{2028}b"), "a·b");
    }

    #[test]
    fn a_long_name_keeps_both_ends_within_the_cap() {
        let exact = "a".repeat(DISPLAY_MAX_CHARS);
        assert!(matches!(display_text(&exact), Cow::Borrowed(_)));

        let long = format!("{}{}", "h".repeat(400), "t".repeat(400));
        let shown = display_text(&long);
        assert_eq!(shown.chars().count(), DISPLAY_MAX_CHARS);
        assert!(shown.starts_with(&"h".repeat(HEAD_CHARS)));
        assert!(shown.ends_with(&"t".repeat(TAIL_CHARS)));
        assert_eq!(shown.chars().nth(HEAD_CHARS), Some(ELLIPSIS));
    }

    #[test]
    fn a_long_name_is_cut_by_code_points_and_still_substituted() {
        let (head, tail) = ("я".repeat(HEAD_CHARS - 1), "😀".repeat(600));
        let long = format!("{head}\u{202E}{tail}");
        let shown = display_text(&long);
        assert_eq!(shown.chars().count(), DISPLAY_MAX_CHARS);
        assert_eq!(shown.chars().nth(HEAD_CHARS - 1), Some(SUBSTITUTE));
        assert!(!shown.chars().any(needs_substitute));
    }

    #[test]
    fn output_never_carries_a_flagged_character() {
        let every: String = (0..=0x10FFFF_u32).filter_map(char::from_u32).collect();
        for chunk in every.as_bytes().chunks(4096) {
            let text = String::from_utf8_lossy(chunk);
            let shown = display_text(&text);
            assert!(!shown.chars().any(needs_substitute));
            assert!(shown.chars().count() <= DISPLAY_MAX_CHARS);
        }
    }
}
