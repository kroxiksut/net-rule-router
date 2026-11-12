//! New sites share a short notification batch; repeats are paced per host.
//! Every surface uses this rule (`siteNoticeDue` in `pure.js` is its twin).

/// A short grouping window between new cards, not between rows in an open card.
pub const SITE_NOTICE_GAP_MS: i64 = 15 * 1000;
/// An earlier unanswered card cannot suppress a confirmed failure for a day.
/// Keep this within the same short batching window as newly discovered sites.
pub const SAME_SITE_GAP_MS: i64 = SITE_NOTICE_GAP_MS;

/// Whether `stamp` is at least `gap` behind `now`. A stamp from the future is
/// a clock that went back, and must not silence the card until it catches up.
fn long_ago(stamp: Option<i64>, now_ms: i64, gap: i64) -> bool {
    stamp.is_none_or(|at| at > now_ms || now_ms - at >= gap)
}

/// Whether a card about a site is due now. `last_any_ms`: when this user was
/// last shown such a card, about any site; `site_shown_ms`: when this site
/// was; `site_answered`: the user answered that card.
#[must_use]
pub fn site_notice_due(
    muted: bool,
    last_any_ms: Option<i64>,
    site_shown_ms: Option<i64>,
    site_answered: bool,
    now_ms: i64,
) -> bool {
    !muted
        && long_ago(last_any_ms, now_ms, SITE_NOTICE_GAP_MS)
        && (site_answered || long_ago(site_shown_ms, now_ms, SAME_SITE_GAP_MS))
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_800_000_000_000;

    #[test]
    fn another_sites_card_does_not_silence_a_new_failure_for_minutes() {
        assert!(
            site_notice_due(false, Some(T - 60_000), None, false, T),
            "a newly confirmed site must not wait half an hour behind another site's card"
        );
        assert!(
            !site_notice_due(false, Some(T - 1_000), None, false, T),
            "a burst of sites belongs in one short notification batch"
        );
        assert!(
            site_notice_due(false, Some(T - 60_000), Some(T - 60_000), false, T),
            "an earlier card must not hide an ongoing failure for a day"
        );
        assert!(!site_notice_due(true, Some(T - 60_000), None, false, T));
    }

    #[test]
    fn a_muted_user_is_never_told() {
        assert!(!site_notice_due(true, None, None, false, T));
    }

    #[test]
    fn bursts_share_a_short_batch_window() {
        assert!(site_notice_due(false, None, None, false, T));
        assert!(!site_notice_due(
            false,
            Some(T - SITE_NOTICE_GAP_MS + 1),
            None,
            false,
            T
        ));
        assert!(site_notice_due(
            false,
            Some(T - SITE_NOTICE_GAP_MS),
            None,
            false,
            T
        ));
        assert!(
            !site_notice_due(false, Some(T - 1), None, true, T),
            "an answer does not bypass the short grouping window"
        );
    }

    #[test]
    fn an_unanswered_site_is_eligible_within_twenty_seconds() {
        let shown = Some(T);
        assert!(!site_notice_due(false, shown, shown, false, T + 14_999));
        assert!(site_notice_due(false, shown, shown, false, T + 15_000));
        assert!(site_notice_due(false, shown, shown, false, T + 20_000));
        assert!(site_notice_due(
            false,
            shown,
            shown,
            false,
            T + 23 * 3_600_000
        ));
        assert!(!site_notice_due(true, shown, shown, false, T + 20_000));
    }

    #[test]
    fn a_clock_that_went_back_does_not_silence_the_card() {
        let later = Some(T + 3_600_000);
        assert!(site_notice_due(false, later, later, false, T));
    }
}
