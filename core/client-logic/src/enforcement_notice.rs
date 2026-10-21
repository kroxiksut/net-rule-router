//! When the rules applying again is worth a line.
//!
//! "Routing works again, reload the pages that failed" answers an outage. The
//! status a fresh install starts in — no main connection chosen yet — is
//! unfinished setup: finishing it applies the rules for the first time, and
//! calling that a recovery tells the user something broke that never ran.

/// The status of a user who has not chosen a main connection yet.
pub const NO_POLICY: &str = "no-policy";

/// Whether the end of `previous` — the status the role held until the rules
/// applied — is worth the restored notice (`enforcementRestoreIsNews`). An
/// unknown previous status counts: a missed outage notice is worse than one
/// line too many.
pub fn restore_is_news(previous: &str) -> bool {
    previous != NO_POLICY
}
