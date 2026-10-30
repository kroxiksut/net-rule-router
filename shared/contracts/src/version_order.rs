//! The one order of product versions: the update offer and every "the service
//! is older than this client" check ask it, whichever client they run in.

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
#[must_use]
pub fn parses_as_version(s: &str) -> bool {
    split_version(s).is_some()
}

/// Prerelease stages, oldest first; the position is the order, not the spelling.
const PRERELEASE_STAGES: [&str; 3] = ["alpha", "beta", "rc"];

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
#[must_use]
pub fn version_is_newer(candidate: &str, current: &str) -> bool {
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
        assert!(version_is_newer("0.2.0", "0.1.0-alpha.1"));
        assert!(version_is_newer("0.1.1", "0.1.0-alpha.1"));
        // Release of the same triple is newer than the alpha build.
        assert!(version_is_newer("0.1.0", "0.1.0-alpha.1"));
        // Not newer: same, older, or the prerelease of the current release.
        assert!(!version_is_newer("0.1.0-alpha.1", "0.1.0-alpha.1"));
        assert!(!version_is_newer("0.1.0-alpha.1", "0.1.0"));
        assert!(!version_is_newer("0.0.9", "0.1.0-alpha.1"));
        // Tag prefixes and build metadata are tolerated.
        assert!(version_is_newer("v1.0.0", "0.1.0-alpha.1"));
        assert!(!version_is_newer("garbage", "0.1.0-alpha.1"));
        assert!(!version_is_newer("1.0", "0.1.0"));
    }

    #[test]
    fn prerelease_stages_order_by_maturity_not_alphabet() {
        let chain = [
            "0.1.0-alpha",
            "0.1.0-alpha.1",
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
        assert!(version_is_newer("0.1.0-ALPHA.2", "0.1.0-alpha.1"));
        assert!(version_is_newer("0.1.0-alpha.2+sha", "0.1.0-alpha.1"));
        assert!(!version_is_newer("0.1.0-alpha.1", "0.1.0-alpha.1"));
    }

    #[test]
    fn an_unknown_prerelease_stage_is_never_offered_nor_outranked() {
        for unknown in ["0.1.0-dev", "0.1.0-nightly", "0.1.0-alpha.x"] {
            for known in ["0.1.0-alpha", "0.1.0-alpha.1", "0.1.0-rc"] {
                assert!(!version_is_newer(unknown, known), "{unknown} vs {known}");
                assert!(!version_is_newer(known, unknown), "{known} vs {unknown}");
            }
        }
        // The triple and the release rule still decide without the stage.
        assert!(version_is_newer("0.1.0", "0.1.0-dev"));
        assert!(version_is_newer("0.2.0-dev", "0.1.0-alpha"));
    }
}
