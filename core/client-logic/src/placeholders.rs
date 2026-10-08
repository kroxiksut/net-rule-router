//! Locale text: `{name}` placeholders and plural categories.

use std::collections::BTreeMap;

/// `text` with each `{name}` replaced by its value, pair by pair in the order
/// given (`fillPlaceholders`).
///
/// The passes are sequential, so a value holding a later pair's `{name}` is
/// filled as well. Callers fill message templates with known values; a log
/// line, whose values come from the outside, goes through [`format_log_line`].
pub fn fill_placeholders<K, V>(text: &str, values: impl IntoIterator<Item = (K, V)>) -> String
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    values
        .into_iter()
        .fold(text.to_owned(), |out, (name, value)| {
            out.replace(&format!("{{{}}}", name.as_ref()), value.as_ref())
        })
}

/// A translated log line with `{name}` taken from `args` and `{0}`, `{1}`…
/// from `positional`, in one pass (`formatLogLine`): a value is never
/// re-scanned, so a `{host}` inside it stays literal.
///
/// A translation left with a hole reads worse than the English line, which
/// still names the cause, so any unfilled placeholder returns `source`.
pub fn format_log_line(
    translated: &str,
    source: &str,
    args: &BTreeMap<String, String>,
    positional: &[impl AsRef<str>],
) -> String {
    fn lookup<'a>(
        name: &str,
        args: &'a BTreeMap<String, String>,
        positional: &'a [impl AsRef<str>],
    ) -> Option<&'a str> {
        if let Some(value) = args.get(name) {
            return Some(value.as_str());
        }
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let index: usize = name.parse().ok()?;
        positional.get(index).map(AsRef::as_ref)
    }

    let mut out = String::with_capacity(translated.len());
    let mut rest = translated;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let name_len = after
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        if name_len > 0 && after.as_bytes().get(name_len) == Some(&b'}') {
            match lookup(&after[..name_len], args, positional) {
                Some(value) => out.push_str(value),
                None => return source.to_owned(),
            }
            rest = &after[name_len + 1..];
        } else {
            out.push('{');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// A plural rule family, as a locale file names it in `label.plural-rule`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PluralRule {
    /// `one` for exactly 1, else `other`. Also every family this build does
    /// not know, so a language added as a file still counts.
    #[default]
    English,
    /// Russian, Ukrainian, Belarusian: `one` / `few` / `many`.
    EastSlavic,
    /// Languages without plural forms: always `other`.
    Invariant,
}

impl PluralRule {
    /// Parses a locale file's family slug.
    pub fn from_slug(slug: &str) -> Self {
        match slug {
            "east-slavic" => Self::EastSlavic,
            "none" => Self::Invariant,
            _ => Self::English,
        }
    }
}

/// A CLDR plural category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluralCategory {
    One,
    Few,
    Many,
    Other,
}

impl PluralCategory {
    /// The CLDR name, the tail of a plural locale key.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::One => "one",
            Self::Few => "few",
            Self::Many => "many",
            Self::Other => "other",
        }
    }
}

/// The category of the whole number `n` under `rule` (`pluralCategory`).
/// A negative count is categorised by its magnitude.
pub fn plural_category(rule: PluralRule, n: i64) -> PluralCategory {
    let k = n.unsigned_abs();
    match rule {
        PluralRule::EastSlavic => {
            let (last, last_two) = (k % 10, k % 100);
            if last == 1 && last_two != 11 {
                PluralCategory::One
            } else if (2..=4).contains(&last) && !(12..=14).contains(&last_two) {
                PluralCategory::Few
            } else {
                PluralCategory::Many
            }
        }
        PluralRule::Invariant => PluralCategory::Other,
        PluralRule::English if k == 1 => PluralCategory::One,
        PluralRule::English => PluralCategory::Other,
    }
}
