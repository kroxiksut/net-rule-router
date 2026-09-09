//! One spelling of an application's identity, for every path that handles one.
//!
//! Windows process names are case-insensitive and a rule may be typed with or
//! without a path and with or without `.exe`, so the same application has many
//! spellings. Every producer of a `CanonicalAppPattern` has to reduce them to
//! one — a validated rule book, a decoded revision, an imported preset — and
//! when one of them skipped it, two representations of the same rule set met in
//! a diff that compares strings: the same rule was reported as added and
//! removed on every pass, forever.
//!
//! Hence this module: the reduction lives here once, and the callers differ
//! only in what they do with the *warnings* it reports.

/// What the reduction had to change, so a validating caller can warn about it.
/// A caller that only needs the value ignores this.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExactNameChanges {
    /// The original spelling, when it carried a directory path.
    pub stripped_path_from: Option<String>,
    /// The name `.exe` was appended to, when it was missing.
    pub appended_exe_to: Option<String>,
}

/// Canonical form of an EXACT process-name match: no directory, lower-case,
/// `.exe` present.
pub fn canonical_exact_process_name(raw: &str) -> (String, ExactNameChanges) {
    let raw = raw.trim();
    let mut changes = ExactNameChanges::default();

    // Handles `C:\Foo\bar.exe`, `C:/Foo/bar.exe` and mixed-separator forms.
    let filename = if raw.contains('/') || raw.contains('\\') {
        let extracted = raw
            .split(['/', '\\'])
            .rfind(|s| !s.is_empty())
            .unwrap_or(raw)
            .to_string();
        changes.stripped_path_from = Some(raw.to_string());
        extracted
    } else {
        raw.to_string()
    };

    let lowercased = filename.to_lowercase();
    if lowercased.ends_with(".exe") {
        (lowercased, changes)
    } else {
        changes.appended_exe_to = Some(filename);
        (format!("{lowercased}.exe"), changes)
    }
}

/// Canonical form of a GLOB process-name match: lower-case only. The user owns
/// the whole pattern, so neither path-stripping nor `.exe` applies — a glob may
/// legitimately end in `*`.
pub fn canonical_glob_process_pattern(raw: &str) -> String {
    raw.trim().to_lowercase()
}

/// The key BOTH sides of an application match are reduced to: file name, lower
/// case, without the `.exe` spelling.
///
/// The suffix is how Windows spells a program, not part of its identity: the
/// same browser is `firefox` in `/proc/<pid>/exe` and `firefox.exe` in a rule
/// canonicalised by [`canonical_exact_process_name`]. Fold it on both sides and
/// the rule matches on either OS; append it on one side only — as the rule
/// store does — and a Linux rule can never match, while a Windows glob that
/// does not end in `.exe` (`*torrent`) never matches either.
pub fn app_match_key(raw: &str) -> String {
    let trimmed = raw.trim();
    let name = trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed);
    let lowered = name.to_ascii_lowercase();
    match lowered.strip_suffix(".exe") {
        // `.exe` alone is a file name, not a suffix on one.
        Some(stem) if !stem.is_empty() => stem.to_string(),
        _ => lowered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_and_path_and_suffix_reduce_to_one_spelling() {
        let (value, changes) =
            canonical_exact_process_name("C:\\Program Files\\SwiftVPN 3.0\\SwiftVPN 3.0.exe");
        assert_eq!(value, "swiftvpn 3.0.exe");
        assert!(changes.stripped_path_from.is_some());
        assert_eq!(changes.appended_exe_to, None);
    }

    #[test]
    fn the_spelling_a_user_types_and_the_one_a_picker_produces_agree() {
        let typed = canonical_exact_process_name("Cloud").0;
        let picked = canonical_exact_process_name("C:/Users/x/AppData/Cloud.exe").0;
        assert_eq!(typed, picked, "these are the same application");
        assert_eq!(typed, "cloud.exe");
    }

    #[test]
    fn a_glob_keeps_its_wildcard_and_loses_only_its_case() {
        assert_eq!(
            canonical_glob_process_pattern("  DiskO*.exe "),
            "disko*.exe"
        );
        assert_eq!(canonical_glob_process_pattern("VendorDis*"), "vendordis*");
    }

    #[test]
    fn canonicalizing_twice_changes_nothing() {
        let once = canonical_exact_process_name("Cloud.exe").0;
        let (twice, changes) = canonical_exact_process_name(&once);
        assert_eq!(once, twice);
        assert_eq!(changes, ExactNameChanges::default());
    }

    #[test]
    fn a_rule_and_a_linux_process_reduce_to_the_same_key() {
        let rule = canonical_exact_process_name("Firefox").0; // "firefox.exe"
        assert_eq!(app_match_key(&rule), app_match_key("/usr/bin/firefox"));
    }

    #[test]
    fn a_rule_and_a_windows_process_reduce_to_the_same_key() {
        let rule = canonical_exact_process_name("Firefox").0;
        assert_eq!(
            app_match_key(&rule),
            app_match_key("C:PATHFirefox.exe".replace("PATH", r"\").as_str())
        );
    }

    #[test]
    fn a_glob_without_the_suffix_still_names_a_windows_process() {
        let pattern = canonical_glob_process_pattern("*Torrent");
        let observed = app_match_key("C:PATHqBittorrent.exe".replace("PATH", r"\").as_str());
        assert_eq!(observed, "qbittorrent");
        assert!(observed.ends_with(pattern.trim_start_matches('*')));
    }

    #[test]
    fn a_name_that_is_only_the_suffix_keeps_it() {
        assert_eq!(app_match_key(".exe"), ".exe");
    }
}
