//! `AppPathResolver` platform port — the neutral contract.
//!
//! An `Application` rule names an executable by its file **name** or a filename
//! **glob** (`2gis.exe`, `DiskO*.exe`). But the packet-filter backends key on a
//! real, on-disk **file path**, not a name — so a name→path bridge is needed or
//! those rules are silently skipped. This port turns a name/glob into the set of
//! concrete exe paths present on the machine so the filter codegen can emit one
//! filter per path.
//!
//! Per the policy/mechanism seam only the PORT + its off-platform
//! default live here; the real mechanism (Windows registry / process list /
//! Program-Files walk; Linux `$PATH` / `.desktop`; macOS `/Applications`) lives
//! in each backend and `impl`s this trait.
//!
//! Resolution is **never an error**: an app that is not installed / not found
//! simply resolves to an empty `Vec`.

use std::collections::HashMap;
use std::path::PathBuf;

/// Resolve an executable NAME or filename-GLOB to the concrete exe paths present
/// on this machine.
///
/// The input is already lowercased, path-stripped and `.exe`-suffixed by the
/// domain layer (e.g. `"2gis.exe"` or `"disko*.exe"`). Returns `0..N` existing
/// exe file paths; an **empty** vector means "unresolved" (app not installed /
/// not found) and is a normal result, never an error.
pub trait AppPathResolver: Send + Sync {
    fn resolve(&self, name_or_glob: &str) -> Vec<PathBuf>;
}

/// Default / off-platform resolver: resolves nothing. Compiles on every OS so the
/// neutral layers can always name a resolver without a `cfg`.
pub struct NoopAppPathResolver;

impl AppPathResolver for NoopAppPathResolver {
    fn resolve(&self, _name_or_glob: &str) -> Vec<PathBuf> {
        Vec::new()
    }
}

// ── Pure helpers (neutral; shared by the Mock and every OS backend) ────────────

/// Case-insensitive filename glob supporting `*` (zero-or-more chars) and `?`
/// (exactly one char). Both `pattern` and `name` are bare file names (no path).
/// A pattern with no metacharacters degenerates to an exact case-insensitive
/// match, which is exactly the non-glob name case.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let pat: Vec<char> = pattern.to_ascii_lowercase().chars().collect();
    let txt: Vec<char> = name.to_ascii_lowercase().chars().collect();
    glob_chars(&pat, &txt)
}

/// Iterative wildcard match with a single backtrack point.
///
/// Deliberately not the recursive `(0..=txt.len()).any(...)` form: that
/// re-explores the same suffixes once per `*` and goes exponential on a pattern
/// like `*a*a*a*a*b`. Patterns arrive from imported rule sets — someone else's
/// file — and this runs on the connection-observation path, so a pathological
/// pattern would wedge that thread rather than merely be slow.
///
/// The algorithm walks both strings once, remembering where the last `*` was
/// and how much text it had consumed; on a mismatch it hands the `*` one more
/// character and resumes. Consecutive stars collapse, since `**` matches
/// exactly what `*` matches.
pub fn glob_chars(pat: &[char], txt: &[char]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    // Where to resume from if the current attempt fails: the pattern index just
    // after the last `*`, and the text index that `*` had reached.
    let mut star: Option<(usize, usize)> = None;

    loop {
        if p < pat.len() && pat[p] == '*' {
            while p < pat.len() && pat[p] == '*' {
                p += 1;
            }
            if p == pat.len() {
                // A trailing `*` matches whatever is left.
                return true;
            }
            star = Some((p, t));
            continue;
        }
        let matched = t < txt.len() && p < pat.len() && (pat[p] == '?' || pat[p] == txt[t]);
        if matched {
            p += 1;
            t += 1;
            continue;
        }
        if p == pat.len() && t == txt.len() {
            return true;
        }
        match star {
            // Give the last `*` one more character and try again.
            Some((resume_p, resume_t)) if resume_t < txt.len() => {
                p = resume_p;
                t = resume_t + 1;
                star = Some((resume_p, t));
            }
            _ => return false,
        }
    }
}

/// Case-insensitive union dedup with a deterministic (sorted) order.
///
/// A resolver may union several sources whose iteration order is not stable
/// (process-enumeration order, filesystem walk order); a canonical
/// case-insensitive sort keeps the codegen's per-path filter ids/weights stable
/// across applies for the same resolved set. Case-insensitivity mirrors the
/// `autostart::paths_match` Windows path convention.
pub fn dedup_paths(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.sort_by(|a, b| {
        a.to_string_lossy()
            .to_ascii_lowercase()
            .cmp(&b.to_string_lossy().to_ascii_lowercase())
    });
    paths.dedup_by(|a, b| {
        a.to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy())
    });
    paths
}

// ── Mock (neutral test double) ────────────────────────────────────────────────

/// In-memory `AppPathResolver` for tests: seeded name → paths. `resolve` applies
/// the same case-insensitive glob the production resolver uses, so a glob query
/// unions every seeded name it matches. Keys are stored lowercased.
#[derive(Default, Clone)]
pub struct MockAppPathResolver {
    map: HashMap<String, Vec<PathBuf>>,
}

impl MockAppPathResolver {
    /// Empty resolver — resolves nothing until seeded.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed one exe name → paths entry (chainable). `name` is stored lowercased.
    #[must_use]
    pub fn with(mut self, name: &str, paths: Vec<PathBuf>) -> Self {
        self.map.insert(name.trim().to_ascii_lowercase(), paths);
        self
    }

    /// Seed from an iterator of `(name, paths)` pairs. Names stored lowercased.
    pub fn from_seed<I: IntoIterator<Item = (String, Vec<PathBuf>)>>(entries: I) -> Self {
        let map = entries
            .into_iter()
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v))
            .collect();
        Self { map }
    }
}

impl AppPathResolver for MockAppPathResolver {
    fn resolve(&self, name_or_glob: &str) -> Vec<PathBuf> {
        let query = name_or_glob.trim();
        if query.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        for (name, paths) in &self.map {
            if glob_match(query, name) {
                out.extend(paths.iter().cloned());
            }
        }
        dedup_paths(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn glob_match_exact_is_case_insensitive() {
        assert!(glob_match("vk.exe", "vk.exe"));
        assert!(glob_match("VK.EXE", "vk.exe"));
        assert!(glob_match("vk.exe", "VK.EXE"));
        assert!(!glob_match("vk.exe", "vkontakte.exe"));
    }

    #[test]
    fn glob_match_star_prefix_suffix_and_middle() {
        assert!(glob_match("disko*.exe", "disko.exe"));
        assert!(glob_match("disko*.exe", "diskosync.exe"));
        assert!(!glob_match("disko*.exe", "disk.exe"));
        assert!(glob_match("*.exe", "anything.exe"));
        assert!(glob_match("2gis*", "2gis.exe"));
        assert!(glob_match("a*b*c.exe", "axxbyyc.exe"));
        assert!(!glob_match("a*b*c.exe", "axxc.exe"));
    }

    #[test]
    fn glob_match_question_mark_is_single_char() {
        assert!(glob_match("vk?.exe", "vk1.exe"));
        assert!(!glob_match("vk?.exe", "vk.exe")); // '?' needs exactly one char
        assert!(!glob_match("vk?.exe", "vk12.exe"));
    }

    #[test]
    fn glob_match_star_matches_empty_run() {
        assert!(glob_match("*", ""));
        assert!(glob_match("vk*", "vk"));
    }

    #[test]
    fn dedup_paths_is_case_insensitive_and_sorted() {
        let out = dedup_paths(vec![
            p(r"C:\B\vk.exe"),
            p(r"C:\A\vk.exe"),
            p(r"c:\a\VK.EXE"), // case-insensitive dup of C:\A\vk.exe
            p(r"C:\A\vk.exe"), // exact dup
        ]);
        assert_eq!(out, vec![p(r"C:\A\vk.exe"), p(r"C:\B\vk.exe")]);
    }

    #[test]
    fn noop_resolver_always_empty() {
        let r = NoopAppPathResolver;
        assert!(r.resolve("vk.exe").is_empty());
        assert!(r.resolve("disko*.exe").is_empty());
    }

    #[test]
    fn mock_exact_lookup_is_case_insensitive() {
        let r = MockAppPathResolver::new().with("vk.exe", vec![p(r"C:\Apps\vk.exe")]);
        assert_eq!(r.resolve("vk.exe"), vec![p(r"C:\Apps\vk.exe")]);
        assert_eq!(r.resolve("VK.EXE"), vec![p(r"C:\Apps\vk.exe")]);
        assert!(r.resolve("other.exe").is_empty());
    }

    #[test]
    fn mock_glob_unions_matching_keys_deterministically() {
        let r = MockAppPathResolver::from_seed([
            ("disko.exe".to_string(), vec![p(r"C:\Yandex\disko.exe")]),
            (
                "diskosync.exe".to_string(),
                vec![p(r"C:\Yandex\diskosync.exe")],
            ),
            ("vk.exe".to_string(), vec![p(r"C:\Apps\vk.exe")]),
        ]);
        assert_eq!(
            r.resolve("disko*.exe"),
            vec![p(r"C:\Yandex\disko.exe"), p(r"C:\Yandex\diskosync.exe")],
        );
        // Non-matching glob → empty.
        assert!(r.resolve("chrome*.exe").is_empty());
    }

    #[test]
    fn mock_empty_query_resolves_nothing() {
        let r = MockAppPathResolver::new().with("vk.exe", vec![p(r"C:\Apps\vk.exe")]);
        assert!(r.resolve("").is_empty());
        assert!(r.resolve("   ").is_empty());
    }
    /// The same answers as the recursive form, without its blow-up.
    ///
    /// The last case is the one that mattered: under the old
    /// `(0..=txt.len()).any(...)` it re-explored every suffix once per star and
    /// took exponential time on a pattern a shared rules file can carry.
    #[test]
    fn glob_matches_the_same_things_and_returns_promptly() {
        assert!(glob_match("*.exe", "chrome.exe"));
        assert!(glob_match("chrome.exe", "CHROME.EXE"));
        assert!(glob_match("c*e.exe", "chrome.exe"));
        assert!(glob_match("chrom?.exe", "chrome.exe"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("**", "anything"));
        assert!(glob_match("*chrome*", "c:/x/chrome.exe"));
        assert!(!glob_match("*.exe", "chrome.dll"));
        assert!(!glob_match("chrom?.exe", "chrome2.exe"));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));

        let started = std::time::Instant::now();
        assert!(!glob_match("*a*a*a*a*a*a*a*a*a*a*b", &"a".repeat(64)));
        assert!(
            started.elapsed() < std::time::Duration::from_millis(200),
            "wildcard match must not backtrack exponentially",
        );
    }
}
