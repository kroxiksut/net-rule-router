//! One spelling of an application's identity, for every path that handles one.
//!
//! A rule may be typed with or without a path, in any case, and on Windows
//! with or without `.exe`, so the same application has many spellings. Every
//! producer of a `CanonicalAppPattern` has to reduce them to one — a validated
//! rule book, a decoded revision, an imported preset — and when one of them
//! skipped it, two representations of the same rule set met in a diff that
//! compares strings: the same rule was reported as added and removed on every
//! pass, forever.
//!
//! Hence this module: the reduction lives here once, and the callers differ
//! only in what they do with the *warnings* it reports.

/// How the platform a rule is written for names its executables.
///
/// The rule's platform decides, never the host doing the reducing: a Windows
/// GUI previewing a `--- Linux` section must leave `telegram` alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutableNaming {
    /// Windows: a program file ends in `.exe`, so a bare name gets it.
    WindowsExe,
    /// Linux and macOS: a program is called exactly what its file is called.
    AsNamed,
}

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
/// and `.exe` present where the platform spells programs that way.
///
/// Lower-casing holds on every platform because every matcher compares
/// case-insensitively ([`app_match_key`], the path resolvers' glob match); a
/// canonical form finer than the match would let two spellings of one rule
/// survive deduplication.
pub fn canonical_exact_process_name(
    raw: &str,
    naming: ExecutableNaming,
) -> (String, ExactNameChanges) {
    let raw = raw.trim();
    let mut changes = ExactNameChanges::default();

    // Handles `C:\Foo\bar.exe`, `C:/Foo/bar.exe`, `/usr/bin/bar` and mixed forms.
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
    if naming == ExecutableNaming::AsNamed || lowercased.ends_with(".exe") {
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
/// same browser is `firefox` in `/proc/<pid>/exe` and `firefox.exe` in a
/// Windows rule. Folding it on both sides lets a rule match whichever spelling
/// it was stored with — a Linux rule stored with `.exe` included — and lets a
/// Windows glob that does not end in `.exe` (`*torrent`) match too.
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

    const WIN: ExecutableNaming = ExecutableNaming::WindowsExe;
    const UNIX: ExecutableNaming = ExecutableNaming::AsNamed;

    #[test]
    fn case_and_path_and_suffix_reduce_to_one_spelling() {
        let (value, changes) =
            canonical_exact_process_name("C:\\Program Files\\SwiftVPN 3.0\\SwiftVPN 3.0.exe", WIN);
        assert_eq!(value, "swiftvpn 3.0.exe");
        assert!(changes.stripped_path_from.is_some());
        assert_eq!(changes.appended_exe_to, None);
    }

    #[test]
    fn the_spelling_a_user_types_and_the_one_a_picker_produces_agree() {
        let typed = canonical_exact_process_name("Cloud", WIN).0;
        let picked = canonical_exact_process_name("C:/Users/x/AppData/Cloud.exe", WIN).0;
        assert_eq!(typed, picked, "these are the same application");
        assert_eq!(typed, "cloud.exe");
    }

    #[test]
    fn a_unix_name_gets_no_suffix_and_reports_none() {
        for name in ["telegram-desktop", "signal-desktop", "org.telegram.desktop"] {
            let (value, changes) = canonical_exact_process_name(name, UNIX);
            assert_eq!(value, name);
            assert_eq!(changes, ExactNameChanges::default(), "{name}");
        }
    }

    #[test]
    fn a_unix_name_is_folded_exactly_as_its_matcher_folds_it() {
        let (value, changes) = canonical_exact_process_name("  /usr/bin/Telegram ", UNIX);
        assert_eq!(value, "telegram");
        assert!(changes.stripped_path_from.is_some());
        assert_eq!(changes.appended_exe_to, None);
        assert_eq!(
            app_match_key(&value),
            app_match_key("/opt/Telegram/Telegram")
        );
    }

    #[test]
    fn a_unix_name_that_really_ends_in_exe_keeps_it() {
        // A Wine-launched program is genuinely called that.
        assert_eq!(
            canonical_exact_process_name("Setup.exe", UNIX).0,
            "setup.exe"
        );
    }

    #[test]
    fn a_glob_keeps_its_wildcard_and_loses_only_its_case() {
        assert_eq!(
            canonical_glob_process_pattern("  DiskO*.exe "),
            "disko*.exe"
        );
        assert_eq!(canonical_glob_process_pattern("VendorDis*"), "vendordis*");
        assert_eq!(canonical_glob_process_pattern("codex*"), "codex*");
    }

    #[test]
    fn canonicalizing_twice_changes_nothing() {
        for naming in [WIN, UNIX] {
            let once = canonical_exact_process_name("Cloud.exe", naming).0;
            let (twice, changes) = canonical_exact_process_name(&once, naming);
            assert_eq!(once, twice);
            assert_eq!(changes, ExactNameChanges::default());
        }
    }

    #[test]
    fn a_rule_and_a_linux_process_reduce_to_the_same_key() {
        let rule = canonical_exact_process_name("Firefox", UNIX).0;
        assert_eq!(app_match_key(&rule), app_match_key("/usr/bin/firefox"));
        // A rule stored with the Windows spelling still names the same program.
        let legacy = canonical_exact_process_name("Firefox", WIN).0;
        assert_eq!(app_match_key(&legacy), app_match_key("/usr/bin/firefox"));
    }

    #[test]
    fn a_rule_and_a_windows_process_reduce_to_the_same_key() {
        let rule = canonical_exact_process_name("Firefox", WIN).0;
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
