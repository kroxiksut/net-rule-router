//! GitHub release check, cache side.
//!
//! Split along the launch path: the LAUNCHER fetches (see
//! `nrr-launcher::update_check_fetch`) and writes a small JSON cache file;
//! THIS module owns the cache location/shape and the read + version-compare
//! consumed by the QML context builder. The scheduled check's result
//! therefore surfaces on the NEXT app start, keeping launch latency zero; the
//! manual check answers its menu item directly.
//!
//! No network code lives here (the GUI crate stays HTTP-free).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use nrr_shared::version_order::parses_as_version;
pub use nrr_shared::version_order::version_is_newer;

/// Public GitHub repository the releases are published under.
pub const RELEASES_REPO: &str = "kroxiksut/net-rule-router";

/// Whether the release check exists in this build. Off until a first release
/// is published: before that the check could only fail, so neither the
/// settings, the Help menu nor the network sees it.
pub const UPDATE_CHECK_AVAILABLE: bool = false;

const DAY_MS: u128 = 24 * 60 * 60 * 1000;

/// Cache payload written by the launcher's fetch thread and read at context
/// build. `latest_tag` keeps the raw GitHub `tag_name` (`v0.2.0` style).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct UpdateCheckCache {
    /// The last successful check, automatic or manual; `0` = none yet.
    pub checked_at_ms: u128,
    /// The first start with the scheduled check on: the clock before any
    /// check, so a fresh install does not ask the network straight away.
    pub first_seen_ms: u128,
    pub latest_tag: String,
    pub html_url: String,
}

/// The cache file, in this user's own application folder. Never the temp
/// directory: off Windows that is `/tmp`, shared by every account, and another
/// user's file there would choose the link this window offers. `None` when
/// the user has no such folder; the check then keeps no cache.
pub fn cache_path() -> Option<PathBuf> {
    let temp = std::env::temp_dir();
    nrr_shared::user_paths::user_app_roots()
        .into_iter()
        .find(|root| !root.starts_with(&temp))
        .map(|root| root.join("update-check.json"))
}

/// Largest cache read: four short fields.
const MAX_CACHE_BYTES: u64 = 16 * 1024;

/// Read the cache; a missing/corrupt file is an empty cache (never an error —
/// the check is strictly best-effort).
pub fn read_cache() -> UpdateCheckCache {
    use std::io::Read;
    let mut text = String::new();
    let read = cache_path()
        .and_then(|path| std::fs::File::open(path).ok())
        .and_then(|file| file.take(MAX_CACHE_BYTES).read_to_string(&mut text).ok());
    read.and_then(|_| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// Where the scheduled check's clock runs from: the last check, else the first
/// start. `None` until either happened.
pub fn clock_start_ms(cache: &UpdateCheckCache) -> Option<u128> {
    [cache.checked_at_ms, cache.first_seen_ms]
        .into_iter()
        .find(|&at| at != 0)
}

/// Should the scheduled check fetch now? Only once `interval_days` passed since
/// [`clock_start_ms`]. A clock start in the future (the system clock was wrong
/// when it was stamped) counts as due, or the check would stall until then.
pub fn is_check_due(cache: &UpdateCheckCache, now_ms: u128, interval_days: u32) -> bool {
    clock_start_ms(cache)
        .is_some_and(|start| now_ms < start || now_ms - start >= u128::from(interval_days) * DAY_MS)
}

/// If the cached latest release is strictly newer than `current_version`,
/// return `(latest_version_display, release_url)` for the GUI notification.
pub fn update_available(current_version: &str) -> Option<(String, String)> {
    let cache = read_cache();
    update_available_from(&cache, current_version)
}

/// Testable core of [`update_available`]. Collapses [`interpret_release`]'s
/// "up to date" and "could not be interpreted" outcomes into `None`: the
/// scheduled check only ever offers an update or stays silent, on this
/// release or a garbled one alike.
pub fn update_available_from(
    cache: &UpdateCheckCache,
    current_version: &str,
) -> Option<(String, String)> {
    match interpret_release(cache, current_version) {
        ReleaseAnswer::UpdateAvailable(version, url) => Some((version, url)),
        ReleaseAnswer::UpToDate | ReleaseAnswer::Unparseable => None,
    }
}

/// What a fetched release compares to. Kept apart from a plain `Option` so a
/// caller that must tell the user something (the manual check) can say "we
/// could not read that" instead of "you are up to date".
#[derive(Debug, PartialEq, Eq)]
pub enum ReleaseAnswer {
    UpdateAvailable(String, String),
    UpToDate,
    /// Present but untrustworthy: no tag, a tag that is not a version, or a
    /// release link outside our own repository.
    Unparseable,
}

/// Classifies a fetched cache against `current_version`.
pub fn interpret_release(cache: &UpdateCheckCache, current_version: &str) -> ReleaseAnswer {
    let latest = cache.latest_tag.trim().trim_start_matches(['v', 'V']);
    if latest.is_empty() || !parses_as_version(latest) {
        return ReleaseAnswer::Unparseable;
    }
    // The cache is an ordinary file in the user's own `%TEMP%`, and this URL
    // ends up at `Qt.openUrlExternally` — which hands whatever scheme it is
    // given to the OS handler. Anything but a release page of the repository we
    // publish from is refused, and refused WHOLE: the tag and the link come out
    // of the same file, so a file that lied about one has not earned belief
    // about the other.
    if !release_url_is_trusted(&cache.html_url) {
        return ReleaseAnswer::Unparseable;
    }
    if version_is_newer(latest, current_version) {
        ReleaseAnswer::UpdateAvailable(latest.to_string(), cache.html_url.clone())
    } else {
        ReleaseAnswer::UpToDate
    }
}

/// The only thing a release link may be: an HTTPS page under `releases` of
/// the repository in [`RELEASES_REPO`] on `github.com`.
///
/// A prefix alone is not that: the browser resolves `..` and its encodings, so
/// `https://github.com/<repo>/../../someone/else` leaves the repository. The
/// path is read segment by segment, and anything a browser could reinterpret —
/// dot segments, escapes, backslashes, a query or a fragment — refuses it.
fn release_url_is_trusted(url: &str) -> bool {
    let Some(path) = url.strip_prefix("https://github.com/") else {
        return false;
    };
    let mut segments = path.split('/');
    let repo_matches = RELEASES_REPO
        .split('/')
        .all(|expected| segments.next() == Some(expected));
    if !repo_matches || segments.next() != Some("releases") {
        return false;
    }
    segments.all(|segment| {
        segment != "."
            && segment != ".."
            && segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_available_respects_cache_and_tag_prefix() {
        let cache = UpdateCheckCache {
            checked_at_ms: 1,
            latest_tag: "v0.2.0".into(),
            html_url: "https://github.com/kroxiksut/net-rule-router/releases/tag/v0.2.0".into(),
            ..UpdateCheckCache::default()
        };
        let hit = update_available_from(&cache, "0.1.0-prealpha").expect("newer");
        assert_eq!(hit.0, "0.2.0");
        assert_eq!(hit.1, cache.html_url);
        assert!(update_available_from(&cache, "0.2.0").is_none());
        assert!(update_available_from(&UpdateCheckCache::default(), "0.1.0").is_none());
    }

    #[test]
    fn a_link_that_is_not_our_release_page_suppresses_the_whole_offer() {
        let newer = |url: &str| UpdateCheckCache {
            checked_at_ms: 1,
            latest_tag: "v9.9.9".into(),
            html_url: url.into(),
            ..UpdateCheckCache::default()
        };
        for hostile in [
            "file:///C:/Windows/System32/calc.exe",
            "ms-settings:",
            "http://github.com/kroxiksut/net-rule-router/releases/tag/v9.9.9",
            "https://github.com.evil.test/kroxiksut/net-rule-router/",
            "https://github.com/someone-else/net-rule-router/releases",
            "https://github.com/kroxiksut/net-rule-router/../../attacker/net-rule-router/releases",
            "https://github.com/kroxiksut/net-rule-router/releases/../../../attacker/x",
            "https://github.com/kroxiksut/net-rule-router/releases/%2e%2e/%2e%2e/attacker",
            "https://github.com/kroxiksut/net-rule-router/releases/tag\\..\\..\\attacker",
            "https://github.com/kroxiksut/net-rule-router/releases/tag/v9?next=//evil.test",
            "https://github.com/kroxiksut/net-rule-router/wiki/evil",
            "https://github.com/kroxiksut/net-rule-router-evil/releases/tag/v9.9.9",
            "",
        ] {
            assert!(
                update_available_from(&newer(hostile), "0.1.0").is_none(),
                "must refuse {hostile:?}",
            );
        }
        // The shape the fetcher actually writes still passes.
        assert!(update_available_from(
            &newer("https://github.com/kroxiksut/net-rule-router/releases/tag/v9.9.9"),
            "0.1.0",
        )
        .is_some());
    }

    #[test]
    fn the_cache_never_lives_in_the_shared_temp_directory() {
        if let Some(path) = cache_path() {
            assert!(
                !path.starts_with(std::env::temp_dir()),
                "{}",
                path.display()
            );
        }
    }

    #[test]
    fn interpret_release_tells_an_unusable_answer_from_a_genuinely_current_one() {
        let with_tag = |tag: &str, url: &str| UpdateCheckCache {
            checked_at_ms: 1,
            latest_tag: tag.into(),
            html_url: url.into(),
            ..UpdateCheckCache::default()
        };
        let trusted = "https://github.com/kroxiksut/net-rule-router/releases/tag/v0.1.0";

        // Genuinely not newer: a real verdict, not an interpretation failure.
        assert_eq!(
            interpret_release(&with_tag("v0.1.0", trusted), "0.1.0"),
            ReleaseAnswer::UpToDate
        );
        // A tag that is not a version, or an untrusted link, is not "up to
        // date" — the answer could not be read at all.
        assert_eq!(
            interpret_release(&with_tag("not-a-version", trusted), "0.1.0"),
            ReleaseAnswer::Unparseable
        );
        assert_eq!(
            interpret_release(&with_tag("", trusted), "0.1.0"),
            ReleaseAnswer::Unparseable
        );
        assert_eq!(
            interpret_release(&with_tag("v9.9.9", "https://example.com/not-ours"), "0.1.0"),
            ReleaseAnswer::Unparseable
        );
        assert_eq!(
            interpret_release(&with_tag("v9.9.9", trusted), "0.1.0"),
            ReleaseAnswer::UpdateAvailable("9.9.9".into(), trusted.into())
        );
    }

    #[test]
    fn check_due_gates_on_the_chosen_interval_from_the_clock_start() {
        let mut cache = UpdateCheckCache::default();
        assert!(
            !is_check_due(&cache, 5_000, 14),
            "no clock yet: the first start stamps it, it does not ask"
        );
        cache.first_seen_ms = 1_000;
        assert!(!is_check_due(&cache, 1_000 + 14 * DAY_MS - 1, 14));
        assert!(is_check_due(&cache, 1_000 + 14 * DAY_MS, 14));
        cache.checked_at_ms = 1_000 + 20 * DAY_MS;
        assert!(
            !is_check_due(&cache, 1_000 + 21 * DAY_MS, 7),
            "the last check, not the first start, runs the clock once there is one"
        );
        assert!(is_check_due(&cache, 1_000 + 27 * DAY_MS, 7));
        assert!(
            is_check_due(&cache, 500, 7),
            "a clock stamped in the future does not stall the check"
        );
    }
}
