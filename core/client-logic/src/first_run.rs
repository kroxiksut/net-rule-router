//! First-run decisions both setups make the same way.

/// The country whose rule set the setup offers first, lowercase ISO 3166
/// (`"ru"`), or `""` when nothing names one. `region` is what the system is
/// set to (Windows "Country or region", the Linux address/time locale) and
/// outranks the language: an English system set to Russia is in Russia.
/// Without it, the first of `locales` decides, a bare language standing for
/// its country as it always has. Twin of `firstRunCountry` in `pure.js`.
pub fn first_run_country(region: &str, locales: &[String]) -> String {
    if let Some(country) = territory(region) {
        return country;
    }
    locales
        .first()
        .and_then(|tag| {
            let tag = normalized(tag)?;
            territory_of(&tag).or_else(|| {
                let language = tag.split('-').next().unwrap_or_default();
                (!language.is_empty()).then(|| language.to_string())
            })
        })
        .unwrap_or_default()
}

/// The territory a tag names: the tag itself when it is a two-letter code,
/// else its first two-letter subtag after the language.
fn territory(tag: &str) -> Option<String> {
    let tag = normalized(tag)?;
    if is_country_code(&tag) {
        return Some(tag);
    }
    territory_of(&tag)
}

fn territory_of(tag: &str) -> Option<String> {
    tag.split('-')
        .skip(1)
        .find(|part| is_country_code(part))
        .map(str::to_string)
}

fn is_country_code(part: &str) -> bool {
    part.len() == 2 && part.bytes().all(|b| b.is_ascii_alphabetic())
}

/// Lowercase, `-`-separated, without encoding or modifier; `None` for the
/// POSIX locale and for nothing.
fn normalized(tag: &str) -> Option<String> {
    let tag = tag
        .split(['.', '@'])
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .replace('_', "-");
    (!tag.is_empty() && tag != "c" && tag != "posix").then_some(tag)
}
