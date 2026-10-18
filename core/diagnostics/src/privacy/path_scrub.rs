//! Absolute file-system paths inside free text.
//!
//! An error string is public by its field name, yet `"cannot open {}: {e}"`
//! carries whatever path the call site had, and file names on the machine are
//! not every reader's business. A path is recognised by its shape — a drive
//! (`C:\`, `C:/`), a share or device prefix (`\\server\`, `\\?\`), a rooted
//! Unix path of two or more segments — in both styles on every OS, and is
//! replaced whole by [`MARKER_MASKED_PATH`]; the sentence around it stays.
//!
//! Not paths: a URL (`https://host/a`, its slashes follow a `:` or a letter),
//! a ratio or prefix length (`1/2`, `10.0.0.0/8`), an IPv6 literal, a relative
//! path, and a single rooted segment (`/flushdns` is a command switch).
//!
//! Byte-oriented and hand-written: every delimiter is ASCII, so a cut never
//! splits a character, and each byte is examined a bounded number of times.

use std::borrow::Cow;

use crate::privacy::redact::{MARKER_MASKED_PATH, MARKER_REDACTED};

/// Longest text scanned. What lies past it is withheld, not passed on unread.
pub const MAX_SCRUB_INPUT_BYTES: usize = 64 * 1024;

/// How far a path may run on past a space (`Program Files (x86)`, a user name
/// with a space in it): a separator must show up within this many words.
const MAX_SPACED_WORDS: usize = 3;
const MAX_SPACED_BYTES: usize = 256;

/// `text` with every absolute path replaced by [`MARKER_MASKED_PATH`];
/// borrowed when there was nothing to replace.
#[must_use]
pub fn mask_absolute_paths(text: &str) -> Cow<'_, str> {
    let overflow = text.len() > MAX_SCRUB_INPUT_BYTES;
    let scanned = if overflow {
        let mut cut = MAX_SCRUB_INPUT_BYTES;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        &text[..cut]
    } else {
        text
    };
    let bytes = scanned.as_bytes();
    let mut out: Option<String> = None;
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        let Some(end) = path_at(bytes, i) else {
            i += 1;
            continue;
        };
        let buf = out.get_or_insert_with(|| String::with_capacity(scanned.len()));
        buf.push_str(&scanned[copied..i]);
        buf.push_str(MARKER_MASKED_PATH);
        copied = end;
        i = end;
    }
    if out.is_none() && !overflow {
        return Cow::Borrowed(text);
    }
    let mut buf = out.unwrap_or_default();
    buf.push_str(&scanned[copied..]);
    if overflow {
        buf.push_str(MARKER_REDACTED);
    }
    Cow::Owned(buf)
}

/// Where a recognised path begins: the first byte after its prefix, and the
/// separator that continues it past a space.
struct Start {
    body_from: usize,
    separator: u8,
    rooted: bool,
}

/// Bytes no path is read through: control characters (line breaks included),
/// quotes, and what neither a Windows nor a sane Unix name holds.
fn is_stop(b: u8) -> bool {
    b.is_ascii_control() || matches!(b, b'"' | b'\'' | b'<' | b'>' | b'|' | b'`')
}

/// What may sit right before a share prefix or a rooted path. `:` is not
/// among them, which is what keeps `https://host/a` whole.
fn opens_path(prev: Option<u8>) -> bool {
    prev.is_none_or(|p| {
        p.is_ascii_control()
            || matches!(
                p,
                b' ' | b'"' | b'\'' | b'(' | b'[' | b'{' | b'<' | b'=' | b',' | b';' | b'`'
            )
    })
}

fn is_segment_start(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'~' | b'$' | b'@') || b >= 0x80
}

fn start_at(bytes: &[u8], i: usize) -> Option<Start> {
    let prev = i.checked_sub(1).map(|p| bytes[p]);
    let at = |k: usize| bytes.get(i + k).copied();
    let first = at(0)?;
    if first.is_ascii_alphabetic() && at(1) == Some(b':') {
        let word_boundary =
            prev.is_none_or(|p| !(p.is_ascii_alphanumeric() || p == b'_' || p >= 0x80));
        return match at(2) {
            Some(separator @ (b'\\' | b'/')) if word_boundary => Some(Start {
                body_from: i + 3,
                separator,
                rooted: false,
            }),
            _ => None,
        };
    }
    if first == b'\\' && at(1) == Some(b'\\') {
        let named = at(2).is_some_and(|b| b != b' ' && !is_stop(b));
        if named && opens_path(prev) {
            return Some(Start {
                body_from: i + 2,
                separator: b'\\',
                rooted: false,
            });
        }
        return None;
    }
    if first == b'/' && opens_path(prev) {
        let body_from = if at(1) == Some(b'/') { i + 2 } else { i + 1 };
        if bytes.get(body_from).is_some_and(|b| is_segment_start(*b)) {
            return Some(Start {
                body_from,
                separator: b'/',
                rooted: true,
            });
        }
    }
    None
}

/// The end (exclusive) of the path starting at `i`, or `None` when none does.
fn path_at(bytes: &[u8], i: usize) -> Option<usize> {
    let start = start_at(bytes, i)?;
    let prev = i.checked_sub(1).map(|p| bytes[p]);
    let closed = prev
        .filter(|&p| matches!(p, b'"' | b'\''))
        .and_then(|quote| closing_quote(bytes, start.body_from, quote));
    let end = match closed {
        Some(close) => close,
        None => {
            let end = unquoted_end(bytes, start.body_from, start.separator);
            trim_trailing(bytes, start.body_from, end)
        }
    };
    // One rooted segment is a switch or a bare directory, not somebody's file.
    if start.rooted && !bytes[start.body_from..end].contains(&b'/') {
        return None;
    }
    Some(end)
}

/// A quoted path runs to its closing quote, spaces and all, unless a control
/// character comes first.
fn closing_quote(bytes: &[u8], from: usize, quote: u8) -> Option<usize> {
    bytes[from..]
        .iter()
        .position(|b| *b == quote || b.is_ascii_control())
        .map(|offset| from + offset)
        .filter(|at| bytes[*at] == quote)
}

fn word_end(bytes: &[u8], from: usize) -> usize {
    bytes[from..]
        .iter()
        .position(|b| *b == b' ' || is_stop(*b))
        .map_or(bytes.len(), |offset| from + offset)
}

fn ends_sentence(b: u8) -> bool {
    matches!(b, b'.' | b',' | b';' | b':' | b'!' | b'?')
}

fn unquoted_end(bytes: &[u8], from: usize, separator: u8) -> usize {
    let mut end = word_end(bytes, from);
    while bytes.get(end) == Some(&b' ') && end > from && !ends_sentence(bytes[end - 1]) {
        match spaced_continuation(bytes, end, separator) {
            Some(next) => end = next,
            None => break,
        }
    }
    end
}

/// Where the path resumes after the space at `space`: the end of the first of
/// the next few words that holds its separator. `None` when prose begins
/// instead — a sentence break, a new path, or too long a stretch.
fn spaced_continuation(bytes: &[u8], space: usize, separator: u8) -> Option<usize> {
    let mut pos = space;
    for _ in 0..MAX_SPACED_WORDS {
        let from = pos + 1;
        let first = *bytes.get(from)?;
        if first == b' ' || is_stop(first) || start_at(bytes, from).is_some() {
            return None;
        }
        let mut j = from;
        let mut has_separator = false;
        while let Some(&b) = bytes.get(j) {
            if b == b' ' || is_stop(b) {
                break;
            }
            if j - space > MAX_SPACED_BYTES {
                return None;
            }
            has_separator |= b == separator;
            j += 1;
        }
        if has_separator {
            return Some(j);
        }
        if bytes.get(j) != Some(&b' ') || ends_sentence(bytes[j - 1]) {
            return None;
        }
        pos = j;
    }
    None
}

/// Trailing punctuation belongs to the sentence; a closing bracket only when
/// the path did not open it (`Program Files (x86)` keeps its own).
fn trim_trailing(bytes: &[u8], from: usize, mut end: usize) -> usize {
    const PAIRS: [(u8, u8); 3] = [(b'(', b')'), (b'[', b']'), (b'{', b'}')];
    let mut depth = [0i64; 3];
    for b in &bytes[from..end] {
        for (k, (open, close)) in PAIRS.iter().enumerate() {
            if b == open {
                depth[k] += 1;
            } else if b == close {
                depth[k] -= 1;
            }
        }
    }
    while end > from {
        let last = bytes[end - 1];
        if ends_sentence(last) {
            end -= 1;
            continue;
        }
        match PAIRS.iter().position(|(_, close)| *close == last) {
            Some(k) if depth[k] < 0 => {
                depth[k] += 1;
                end -= 1;
            }
            _ => break,
        }
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masked(text: &str) -> String {
        mask_absolute_paths(text).into_owned()
    }

    #[test]
    fn a_drive_path_is_masked_whole_and_the_os_error_stays() {
        assert_eq!(
            masked(r"cannot open C:\Users\alice\rules.txt: Access is denied. (os error 5)"),
            "cannot open <masked-path>: Access is denied. (os error 5)"
        );
        assert_eq!(masked("path=D:/Users/alice/x.txt"), "path=<masked-path>");
    }

    #[test]
    fn a_share_and_a_device_prefix_are_paths() {
        for text in [
            r"\\server\home\alice\notes.txt",
            r"\\?\C:\Users\alice\AppData",
            r"\\.\pipe\some-name",
        ] {
            assert_eq!(masked(text), MARKER_MASKED_PATH, "{text}");
        }
    }

    #[test]
    fn a_rooted_unix_path_is_masked() {
        assert_eq!(
            masked("open /home/alice/.config/rules.txt: No such file (os error 2)"),
            "open <masked-path>: No such file (os error 2)"
        );
        assert_eq!(masked("//server/share/x"), MARKER_MASKED_PATH);
    }

    #[test]
    fn a_space_inside_a_path_does_not_end_it() {
        assert_eq!(
            masked(r"C:\Program Files (x86)\Vendor App\app.exe failed to start"),
            "<masked-path> failed to start"
        );
        assert_eq!(
            masked(r"read C:\Users\John Smith\notes.txt: denied"),
            "read <masked-path>: denied"
        );
        assert_eq!(
            masked("/home/alice/My Documents/a.txt is gone"),
            "<masked-path> is gone"
        );
    }

    #[test]
    fn a_quoted_path_ends_at_its_quote() {
        assert_eq!(
            masked(r#"failed to read "C:\Users\John Smith" (denied)"#),
            r#"failed to read "<masked-path>" (denied)"#
        );
        // A `{:?}`-formatted path doubles its backslashes.
        assert_eq!(
            masked(r#"Os { path: "C:\\Users\\alice\\x" }"#),
            r#"Os { path: "<masked-path>" }"#
        );
        assert_eq!(masked("'/var/lib/nrr/x.db'"), "'<masked-path>'");
    }

    #[test]
    fn trailing_punctuation_and_an_outer_bracket_stay_outside() {
        assert_eq!(masked("see /var/lib/nrr."), "see <masked-path>.");
        assert_eq!(masked(r"(C:\x\y)"), "(<masked-path>)");
        assert_eq!(masked(r"[C:\x\y], next"), "[<masked-path>], next");
    }

    #[test]
    fn two_paths_in_one_sentence_stay_two() {
        assert_eq!(
            masked(r"copy C:\a\b to D:\c\d"),
            "copy <masked-path> to <masked-path>"
        );
        assert_eq!(
            masked("rename /a/b -> /c/d"),
            "rename <masked-path> -> <masked-path>"
        );
    }

    #[test]
    fn text_without_a_path_comes_back_borrowed() {
        let text = "connection refused (os error 111)";
        assert!(matches!(mask_absolute_paths(text), Cow::Borrowed(t) if t == text));
        assert!(matches!(mask_absolute_paths(""), Cow::Borrowed("")));
    }

    #[test]
    fn a_url_is_not_a_path() {
        for text in [
            "https://example.test/a/b?x=1",
            "fetch http://example.test/releases/latest failed",
        ] {
            assert_eq!(masked(text), text);
        }
    }

    #[test]
    fn a_ratio_a_prefix_length_and_ipv6_are_not_paths() {
        for text in [
            "1/2 done",
            "10.0.0.0/8",
            "fe80::1",
            "fe80::1/64",
            "[2001:db8::1]:53",
            "3 KiB/s",
            "and/or",
            "drive C: is full",
        ] {
            assert_eq!(masked(text), text);
        }
    }

    #[test]
    fn a_single_rooted_segment_is_a_switch_not_a_path() {
        for text in ["ipconfig /flushdns failed", "/tmp", "a / b"] {
            assert_eq!(masked(text), text);
        }
    }

    #[test]
    fn a_relative_path_is_not_absolute() {
        for text in [r"rules\primary.txt", "logs/x.ndjson", "~/notes"] {
            assert_eq!(masked(text), text);
        }
    }

    /// A file URL names a file on this machine, so its path goes.
    #[test]
    fn a_file_url_loses_its_path() {
        assert_eq!(
            masked("file:///C:/Users/alice/x.txt"),
            "file:///<masked-path>"
        );
    }

    #[test]
    fn non_ascii_names_are_masked_and_never_split() {
        assert_eq!(
            masked(r"ошибка: C:\Пользователи\Алиса\файл.txt — нет доступа"),
            "ошибка: <masked-path> — нет доступа"
        );
        assert_eq!(masked("/home/алиса/файл"), MARKER_MASKED_PATH);
    }

    #[test]
    fn text_past_the_bound_is_withheld_not_passed_unread() {
        // A two-byte character straddles the cut.
        let text = format!(
            "{}ж{}",
            "a".repeat(MAX_SCRUB_INPUT_BYTES - 1),
            "/home/alice/x"
        );
        let out = masked(&text);
        assert!(out.ends_with(MARKER_REDACTED), "{}", &out[out.len() - 20..]);
        assert!(!out.contains("alice"));
        assert!(out.len() <= MAX_SCRUB_INPUT_BYTES + MARKER_REDACTED.len());
    }

    #[test]
    fn a_second_pass_finds_nothing_left() {
        for text in [
            r"cannot open C:\Users\alice\rules.txt: denied",
            r#""C:\a b" and '/c/d e' then \\srv\x"#,
            r"C:\Program Files (x86)\App\a.exe) (x",
            "/a/b.)]}",
        ] {
            let once = masked(text);
            assert_eq!(masked(&once), once, "{text}");
        }
    }

    #[test]
    fn pathological_runs_stay_linear_and_never_panic() {
        for unit in ["/a=", "\"/a ", r"C:\ ", r"\\", "x y ", "'/a'", ") "] {
            let text = unit.repeat(MAX_SCRUB_INPUT_BYTES / unit.len());
            let _ = mask_absolute_paths(&text);
        }
    }
}
