//! Once-a-day GitHub release check, cache side.
//!
//! Split along the launch path: the LAUNCHER fetches (background thread,
//! never blocks startup — see `nrr-launcher::update_check_fetch`) and writes
//! a small JSON cache file; THIS module owns the cache location/shape and the
//! read + version-compare consumed by the QML context builder. Consequence of
//! the split: a newer release becomes visible on the NEXT app start after the
//! fetch — acceptable for a daily cadence, and launch latency stays zero.
//!
//! No network code lives here (the GUI crate stays HTTP-free).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Public GitHub repository the releases are published under.
pub const RELEASES_REPO: &str = "kroxiksut/net-rule-router";

/// Minimum interval between two release fetches (24 h), in milliseconds.
pub const CHECK_INTERVAL_MS: u128 = 24 * 60 * 60 * 1000;

/// Cache payload written by the launcher's fetch thread and read at context
/// build. `latest_tag` keeps the raw GitHub `tag_name` (`v0.2.0` style).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct UpdateCheckCache {
    pub checked_at_ms: u128,
    pub latest_tag: String,
    pub html_url: String,
}

/// The cache file, next to the launcher logs in `%TEMP%\NetRuleRouter`.
pub fn cache_path() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push("NetRuleRouter");
    path.push("update-check.json");
    path
}

/// Read the cache; a missing/corrupt file is an empty cache (never an error —
/// the check is strictly best-effort).
pub fn read_cache() -> UpdateCheckCache {
    std::fs::read_to_string(cache_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Should the launcher fetch now? True when there never was a successful
/// check (`checked_at_ms == 0`) or the last one is older than
/// [`CHECK_INTERVAL_MS`].
pub fn is_check_due(cache: &UpdateCheckCache, now_ms: u128) -> bool {
    cache.checked_at_ms == 0 || now_ms.saturating_sub(cache.checked_at_ms) >= CHECK_INTERVAL_MS
}

/// If the cached latest release is strictly newer than `current_version`,
/// return `(latest_version_display, release_url)` for the GUI notification.
pub fn update_available(current_version: &str) -> Option<(String, String)> {
    let cache = read_cache();
    update_available_from(&cache, current_version)
}

/// Testable core of [`update_available`].
pub fn update_available_from(
    cache: &UpdateCheckCache,
    current_version: &str,
) -> Option<(String, String)> {
    let latest = cache.latest_tag.trim().trim_start_matches(['v', 'V']);
    if latest.is_empty() {
        return None;
    }
    if version_is_newer(latest, current_version) {
        Some((latest.to_string(), cache.html_url.clone()))
    } else {
        None
    }
}

/// Strict "is `candidate` newer than `current`" over `MAJOR.MINOR.PATCH
/// [-prerelease]` version strings. Deliberately minimal instead of a semver
/// dependency: numeric triple compares first; on an equal triple, a release
/// (no prerelease suffix) is newer than any prerelease, and two prereleases
/// compare lexicographically (enough for `-prealpha` → `-alpha` → `-beta`
/// style chains; we control both sides). Unparseable input → `false` (never
/// nag on garbage).
fn version_is_newer(candidate: &str, current: &str) -> bool {
    fn split(v: &str) -> Option<([u64; 3], Option<String>)> {
        let v = v.trim().trim_start_matches(['v', 'V']);
        let (core, pre) = match v.split_once('-') {
            Some((core, pre)) => (core, Some(pre.to_ascii_lowercase())),
            None => (v, None),
        };
        // Ignore build metadata (`+sha`).
        let core = core.split('+').next().unwrap_or(core);
        let mut nums = [0u64; 3];
        let mut parts = core.split('.');
        for slot in &mut nums {
            *slot = parts.next()?.trim().parse().ok()?;
        }
        if parts.next().is_some() {
            return None;
        }
        Some((nums, pre))
    }
    let (Some((cand, cand_pre)), Some((cur, cur_pre))) = (split(candidate), split(current)) else {
        return false;
    };
    if cand != cur {
        return cand > cur;
    }
    match (cand_pre, cur_pre) {
        // Same triple: a release beats a prerelease.
        (None, Some(_)) => true,
        (Some(_), None) => false,
        (None, None) => false,
        (Some(a), Some(b)) => a > b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_versions_are_detected_and_prerelease_orders_below_release() {
        assert!(version_is_newer("0.2.0", "0.1.0-prealpha"));
        assert!(version_is_newer("0.1.1", "0.1.0-prealpha"));
        // Release of the same triple is newer than the prealpha build.
        assert!(version_is_newer("0.1.0", "0.1.0-prealpha"));
        // Not newer: same, older, or the prerelease of the current release.
        assert!(!version_is_newer("0.1.0-prealpha", "0.1.0-prealpha"));
        assert!(!version_is_newer("0.1.0-prealpha", "0.1.0"));
        assert!(!version_is_newer("0.0.9", "0.1.0-prealpha"));
        // Tag prefixes and build metadata are tolerated.
        assert!(version_is_newer("v1.0.0", "0.1.0-prealpha"));
        assert!(!version_is_newer("garbage", "0.1.0-prealpha"));
        assert!(!version_is_newer("1.0", "0.1.0"));
    }

    #[test]
    fn update_available_respects_cache_and_tag_prefix() {
        let cache = UpdateCheckCache {
            checked_at_ms: 1,
            latest_tag: "v0.2.0".into(),
            html_url: "https://example.test/rel".into(),
        };
        let hit = update_available_from(&cache, "0.1.0-prealpha").expect("newer");
        assert_eq!(hit.0, "0.2.0");
        assert_eq!(hit.1, "https://example.test/rel");
        assert!(update_available_from(&cache, "0.2.0").is_none());
        assert!(update_available_from(&UpdateCheckCache::default(), "0.1.0").is_none());
    }

    #[test]
    fn check_due_gates_on_the_daily_interval() {
        let mut cache = UpdateCheckCache::default();
        assert!(is_check_due(&cache, 0), "empty cache → due");
        cache.checked_at_ms = 1_000;
        assert!(!is_check_due(&cache, 1_000 + CHECK_INTERVAL_MS - 1));
        assert!(is_check_due(&cache, 1_000 + CHECK_INTERVAL_MS));
    }
}
