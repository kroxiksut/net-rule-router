//! Suffixes of home and local networks, and what counts as one.
//!
//! Names under such a suffix (`printer.lan`, `nas.fritz.box`) belong to the
//! network the machine is on, not to the internet, so the product leaves them
//! to that network's own resolver. The list is one per machine, pre-filled
//! with the suffixes home routers hand out, and only an administrator changes
//! it: a suffix the current network offers over DHCP is shown as an offer,
//! never applied by itself — a network can name anything, including the
//! domain of a site the user routes.
//!
//! Pure: the service validates what it stores with it and the clients explain
//! a refusal with it. The OS mechanism that acts on the list stays behind the
//! DNS redirect port.

/// What a fresh machine starts with.
pub const DEFAULT_SUFFIXES: [&str; 4] = ["home.arpa", "lan", "local", "fritz.box"];

/// Most entries the list may hold. Each becomes a resolver rule the OS
/// consults per lookup, and nobody runs more home networks than this.
pub const MAX_SUFFIXES: usize = 64;

/// The longest name DNS carries.
const MAX_SUFFIX_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Why a suffix was refused. The slug is what a client translates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuffixRejection {
    /// Nothing left after trimming dots and spaces.
    Empty,
    /// Longer than a DNS name may be, or a label longer than 63 characters.
    TooLong,
    /// A character outside letters, digits and hyphens, or a label that starts
    /// or ends with a hyphen.
    BadLabel,
    /// More entries than [`MAX_SUFFIXES`].
    TooMany,
}

impl SuffixRejection {
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooLong => "too-long",
            Self::BadLabel => "bad-label",
            Self::TooMany => "too-many",
        }
    }
}

/// `raw` as the list stores it: lower-case, no surrounding dots or spaces,
/// every label a hostname label. Bounded and total — the input may come from
/// a DHCP lease or an IPC frame.
pub fn normalize_suffix(raw: &str) -> Result<String, SuffixRejection> {
    let trimmed = raw.trim().trim_matches('.');
    if trimmed.is_empty() {
        return Err(SuffixRejection::Empty);
    }
    if trimmed.len() > MAX_SUFFIX_LEN {
        return Err(SuffixRejection::TooLong);
    }
    let lowered = trimmed.to_ascii_lowercase();
    for label in lowered.split('.') {
        if label.is_empty() {
            return Err(SuffixRejection::BadLabel);
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(SuffixRejection::TooLong);
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(SuffixRejection::BadLabel);
        }
    }
    Ok(lowered)
}

/// A whole list as the service stores it: each entry normalised, duplicates
/// dropped, order kept, the count bounded. The first bad entry refuses the
/// list, so an administrator never saves half of what they typed.
pub fn normalize_list(raw: &[String]) -> Result<Vec<String>, (usize, SuffixRejection)> {
    let mut out: Vec<String> = Vec::with_capacity(raw.len().min(MAX_SUFFIXES));
    for (index, entry) in raw.iter().enumerate() {
        let suffix = normalize_suffix(entry).map_err(|why| (index, why))?;
        if out.contains(&suffix) {
            continue;
        }
        if out.len() == MAX_SUFFIXES {
            return Err((index, SuffixRejection::TooMany));
        }
        out.push(suffix);
    }
    Ok(out)
}

/// Does `host` fall under `suffix`? The suffix itself counts, and anything
/// under it on a label boundary: `notcorp.example` is not under `corp.example`.
/// Both are compared as [`normalize_suffix`] would store them.
#[must_use]
pub fn covers(suffix: &str, host: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let suffix = suffix.trim().trim_matches('.').to_ascii_lowercase();
    if suffix.is_empty() || host.is_empty() {
        return false;
    }
    if host == suffix {
        return true;
    }
    host.strip_suffix(&suffix)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

/// The rule hosts a suffix would take away if it were honoured for them.
/// Sorted and de-duplicated, so a warning reads the same on every screen.
#[must_use]
pub fn covered_hosts<'a>(suffix: &str, hosts: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = hosts
        .into_iter()
        .filter(|host| covers(suffix, host))
        .map(|host| host.trim().trim_end_matches('.').to_ascii_lowercase())
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_valid_as_written() {
        for suffix in DEFAULT_SUFFIXES {
            assert_eq!(normalize_suffix(suffix).as_deref(), Ok(suffix));
        }
    }

    #[test]
    fn a_suffix_is_stored_the_way_every_comparison_expects() {
        assert_eq!(
            normalize_suffix("  .Home.ARPA. ").as_deref(),
            Ok("home.arpa")
        );
        assert_eq!(normalize_suffix("fritz.box").as_deref(), Ok("fritz.box"));
        assert_eq!(normalize_suffix("lan").as_deref(), Ok("lan"));
    }

    /// Anything a DHCP lease or a frame can carry is refused with a reason,
    /// never trusted and never a panic.
    #[test]
    fn hostile_or_broken_input_is_refused_with_a_reason() {
        assert_eq!(normalize_suffix(" . "), Err(SuffixRejection::Empty));
        assert_eq!(normalize_suffix(""), Err(SuffixRejection::Empty));
        assert_eq!(normalize_suffix("a..b"), Err(SuffixRejection::BadLabel));
        assert_eq!(normalize_suffix("-lan"), Err(SuffixRejection::BadLabel));
        assert_eq!(normalize_suffix("lan-"), Err(SuffixRejection::BadLabel));
        assert_eq!(normalize_suffix("l an"), Err(SuffixRejection::BadLabel));
        assert_eq!(normalize_suffix("a<b>.c"), Err(SuffixRejection::BadLabel));
        assert_eq!(
            normalize_suffix("дом.local"),
            Err(SuffixRejection::BadLabel)
        );
        assert_eq!(
            normalize_suffix(&"a".repeat(64)),
            Err(SuffixRejection::TooLong)
        );
        let long = ["abcdefghij"; 30].join(".");
        assert_eq!(normalize_suffix(&long), Err(SuffixRejection::TooLong));
        assert_eq!(normalize_suffix("\0"), Err(SuffixRejection::BadLabel));
    }

    #[test]
    fn a_list_keeps_order_drops_duplicates_and_names_the_bad_entry() {
        let raw: Vec<String> = ["LAN", "lan.", "home.arpa"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(
            normalize_list(&raw),
            Ok(vec!["lan".into(), "home.arpa".into()])
        );
        let raw: Vec<String> = ["lan", "bad label", "home.arpa"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(normalize_list(&raw), Err((1, SuffixRejection::BadLabel)));
        let raw: Vec<String> = (0..=MAX_SUFFIXES).map(|n| format!("n{n}.lan")).collect();
        assert_eq!(
            normalize_list(&raw),
            Err((MAX_SUFFIXES, SuffixRejection::TooMany))
        );
    }

    #[test]
    fn coverage_stops_at_a_label_boundary() {
        assert!(covers("corp.example", "corp.example"));
        assert!(covers("corp.example", "host.corp.example."));
        assert!(covers("corp.example", "A.B.Corp.Example"));
        assert!(!covers("corp.example", "notcorp.example"));
        assert!(!covers("corp.example", "corp.example.evil"));
        assert!(!covers("lan", "lan.example"));
        assert!(!covers("", "host"));
        assert!(!covers("lan", ""));
    }

    #[test]
    fn covered_hosts_is_what_a_warning_lists() {
        let hosts = [
            "b.corp.example",
            "a.corp.example",
            "www.example",
            "A.corp.example",
        ];
        assert_eq!(
            covered_hosts("corp.example", hosts),
            vec!["a.corp.example".to_string(), "b.corp.example".to_string()]
        );
        assert!(covered_hosts("lan", hosts).is_empty());
    }
}
