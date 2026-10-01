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

/// Public GitHub repository the releases are published under.
pub const RELEASES_REPO: &str = "kroxiksut/net-rule-router";

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

/// The cache file, next to the launcher logs in `%TEMP%\NetRuleRouter`.
pub fn cache_path() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(nrr_shared::product_identity::PRODUCT_NAME);
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

/// The only thing a release link may be: an HTTPS page under the repository in
/// [`RELEASES_REPO`].
///
/// A prefix test rather than a URL parse: the set of acceptable links has
/// exactly one shape, and a parser would answer a question nobody asked while
/// adding a dependency to a module that deliberately has none.
fn release_url_is_trusted(url: &str) -> bool {
    let expected = format!("https://github.com/{RELEASES_REPO}/");
    url.starts_with(&expected)
}

/// Parses `MAJOR.MINOR.PATCH[-prerelease]` (leading `v`/`V` and `+build`
/// metadata tolerated). `None` when `v` does not have that shape.
fn split_version(v: &str) -> Option<([u64; 3], Option<String>)> {
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

/// Whether `s` has the `MAJOR.MINOR.PATCH[-prerelease]` shape at all — used to
/// tell a garbled release answer from a genuinely older one.
fn parses_as_version(s: &str) -> bool {
    split_version(s).is_some()
}

/// Prerelease stages, oldest first. Alphabetical order would put `prealpha`
/// after `alpha` and never offer the first alpha to a prealpha build.
const PRERELEASE_STAGES: [&str; 4] = ["prealpha", "alpha", "beta", "rc"];

/// `(stage, number)` of a prerelease tag such as `alpha`, `beta.2` or `rc1`;
/// a missing number is 0. `None` for a stage outside [`PRERELEASE_STAGES`].
fn prerelease_rank(tag: &str) -> Option<(usize, u64)> {
    let tag = tag.split('+').next().unwrap_or(tag);
    let stage_len = tag
        .find(|c: char| !c.is_ascii_alphabetic())
        .unwrap_or(tag.len());
    let (stage, rest) = tag.split_at(stage_len);
    let rank = PRERELEASE_STAGES.iter().position(|s| *s == stage)?;
    let rest = rest.strip_prefix(['.', '-']).unwrap_or(rest);
    let number = if rest.is_empty() {
        0
    } else {
        rest.parse().ok()?
    };
    Some((rank, number))
}

/// Strict "is `candidate` newer than `current`" over `MAJOR.MINOR.PATCH
/// [-prerelease]` version strings. Deliberately minimal instead of a semver
/// dependency: numeric triple compares first; on an equal triple, a release
/// (no prerelease suffix) is newer than any prerelease, and two prereleases
/// compare by [`PRERELEASE_STAGES`], then by number. Unparseable input or an
/// unknown stage → `false` (never nag on what we cannot order).
fn version_is_newer(candidate: &str, current: &str) -> bool {
    let (Some((cand, cand_pre)), Some((cur, cur_pre))) =
        (split_version(candidate), split_version(current))
    else {
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
        (Some(a), Some(b)) => match (prerelease_rank(&a), prerelease_rank(&b)) {
            (Some(a), Some(b)) => a > b,
            _ => false,
        },
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
    fn prerelease_stages_order_by_maturity_not_alphabet() {
        let chain = [
            "0.1.0-prealpha",
            "0.1.0-alpha",
            "0.1.0-beta",
            "0.1.0-rc",
            "0.1.0",
        ];
        for (i, newer) in chain.iter().enumerate() {
            for (j, older) in chain.iter().enumerate() {
                assert_eq!(version_is_newer(newer, older), i > j, "{newer} vs {older}");
            }
        }
    }

    #[test]
    fn a_numbered_prerelease_orders_within_its_stage() {
        assert!(version_is_newer("0.1.0-alpha.2", "0.1.0-alpha.1"));
        assert!(version_is_newer("0.1.0-alpha.1", "0.1.0-alpha"));
        assert!(version_is_newer("0.1.0-beta.10", "0.1.0-beta.9"));
        assert!(version_is_newer("0.1.0-rc2", "0.1.0-rc1"));
        assert!(version_is_newer("0.1.0-beta", "0.1.0-alpha.9"));
        assert!(version_is_newer("0.1.0-ALPHA", "0.1.0-prealpha"));
        assert!(version_is_newer("0.1.0-alpha+sha", "0.1.0-prealpha"));
        assert!(!version_is_newer("0.1.0-alpha.1", "0.1.0-alpha.1"));
    }

    #[test]
    fn an_unknown_prerelease_stage_is_never_offered_nor_outranked() {
        for unknown in ["0.1.0-dev", "0.1.0-nightly", "0.1.0-alpha.x"] {
            for known in ["0.1.0-prealpha", "0.1.0-alpha", "0.1.0-rc"] {
                assert!(!version_is_newer(unknown, known), "{unknown} vs {known}");
                assert!(!version_is_newer(known, unknown), "{known} vs {unknown}");
            }
        }
        // The triple and the release rule still decide without the stage.
        assert!(version_is_newer("0.1.0", "0.1.0-dev"));
        assert!(version_is_newer("0.2.0-dev", "0.1.0-alpha"));
    }

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
