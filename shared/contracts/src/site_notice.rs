//! How often "a site does not open" may be told, by any surface.
//!
//! The service that starts the tray for one card and a running tray that pops
//! the card itself decide by this one rule (`siteNoticeDue` in `pure.js` is
//! its twin), so a closed tray and an open one behave alike: nothing once the
//! user muted the kind, at most one card per [`SITE_NOTICE_GAP_MS`] whatever
//! the site, and the same site not again within [`SAME_SITE_GAP_MS`] unless
//! the user answered its last card.

/// Least time between two cards for one user.
pub const SITE_NOTICE_GAP_MS: i64 = 30 * 60 * 1000;
/// Least time before the same site is told again, unanswered.
pub const SAME_SITE_GAP_MS: i64 = 24 * 60 * 60 * 1000;

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
    fn a_muted_user_is_never_told() {
        assert!(!site_notice_due(true, None, None, false, T));
    }

    #[test]
    fn one_card_per_half_hour_whatever_the_site() {
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
            "an answer does not lift the half hour"
        );
    }

    #[test]
    fn the_same_site_waits_a_day_unless_its_card_was_answered() {
        let shown = Some(T - SITE_NOTICE_GAP_MS);
        assert!(!site_notice_due(false, shown, shown, false, T));
        assert!(site_notice_due(false, shown, shown, true, T));
        let yesterday = Some(T - SAME_SITE_GAP_MS);
        assert!(site_notice_due(false, yesterday, yesterday, false, T));
    }

    #[test]
    fn a_clock_that_went_back_does_not_silence_the_card() {
        let later = Some(T + 3_600_000);
        assert!(site_notice_due(false, later, later, false, T));
    }
}
