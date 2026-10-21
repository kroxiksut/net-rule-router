//! The agreement revision the app requires. The text lives in
//! `docs/legal/eula.<lang>.md`; only the number is compiled in, because the
//! first-run gate and the QML context must agree on it.

/// Bump together with the `Редакция соглашения N` header of
/// `docs/legal/eula.ru.md` when the terms change, or users who accepted an
/// older text are never asked again. `0` is the "never accepted" sentinel.
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
