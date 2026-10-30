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

/// The locale key that says what happens while the additional connection is
/// down, by the user's leak protection (`enforcementSecondaryDownBodyKey`):
/// with it off the rules' sites go over the main one, under `everything` the
/// whole internet waits. An unknown level keeps the `sites` wording.
pub fn secondary_down_body_key(leak_protection: &str) -> &'static str {
    match leak_protection {
        "off" => "notifications.enforcement.secondary-down.body-off",
        "everything" => "notifications.enforcement.secondary-down.body-everything",
        _ => "notifications.enforcement.secondary-down.body",
    }
}

/// The body of an adapter-choice notice naming `count` adapters
/// (`enforcementAdapterChoiceBodyKey`): one is a similar adapter that is up
/// while the saved one is not, several are names to choose between.
pub fn adapter_choice_body_key(count: usize) -> &'static str {
    if count == 1 {
        "notifications.enforcement.adapter-choice.body-one"
    } else {
        "notifications.enforcement.adapter-choice.body"
    }
}
