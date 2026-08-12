//! End-user license agreement (EULA) versioning — the single source of truth
//! for which agreement revision the app currently requires the user to accept.
//!
//! The agreement text itself lives outside the code (`docs/legal/eula.<lang>.md`)
//! and is loaded into the QML context at launch. Only the *version number* is
//! a compiled constant, because two independent layers must agree on it:
//!
//! - the GUI first-run gate compares the persisted
//!   `UiPreferences.accepted_eula_version` against [`CURRENT_EULA_VERSION`] and
//!   re-shows the agreement whenever the persisted value is lower (the behaviour
//!   the agreement's own "Изменение условий" clause promises);
//! - the context emitter stamps [`CURRENT_EULA_VERSION`] into the QML context so
//!   the QML side records the right number on acceptance.
//!
//! Bumping the agreement text in `docs/legal/` is only legally meaningful if
//! this constant is bumped in the same change — otherwise previously-accepted
//! users are never re-prompted. Keep the number in sync with the `Версия N`
//! header line of `docs/legal/eula.ru.md`.

/// The EULA revision the current build requires. Starts at `1`. Bump in lockstep
/// with the `Версия N` header of `docs/legal/eula.ru.md` whenever the terms
/// change in a way that requires re-acceptance. `0` is reserved as the
/// "never accepted" sentinel for `UiPreferences.accepted_eula_version`.
pub const CURRENT_EULA_VERSION: u32 = 1;

/// The sentinel persisted for a user who has never accepted any agreement.
pub const EULA_NOT_ACCEPTED: u32 = 0;

/// Whether an agreement of the given previously-accepted version still satisfies
/// the current build, i.e. no re-prompt is needed.
#[must_use]
pub const fn is_accepted(accepted_version: u32) -> bool {
    accepted_version >= CURRENT_EULA_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_accepted_sentinel_requires_prompt() {
        assert!(!is_accepted(EULA_NOT_ACCEPTED));
    }

    #[test]
    fn current_version_is_accepted() {
        assert!(is_accepted(CURRENT_EULA_VERSION));
    }

    #[test]
    fn a_future_acceptance_still_counts() {
        assert!(is_accepted(CURRENT_EULA_VERSION + 1));
    }
}
