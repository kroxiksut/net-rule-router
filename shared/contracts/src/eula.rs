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

/// An installer's record that one account accepted the agreement on its licence
/// page. Not a security gate: it only spares that account a second reading.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallerAcceptance {
    version: u32,
    account: String,
}

impl InstallerAcceptance {
    /// `None` for anything that cannot be such a record: the account must be
    /// a security identifier in its text form (`S-1-5-21-…`).
    #[must_use]
    pub fn new(version: u32, account: &str) -> Option<Self> {
        is_account_id(account).then(|| Self {
            version,
            account: account.to_owned(),
        })
    }
}

/// Whether the account this program runs as accepted, in the installer, the
/// very agreement the program asks for. Unsure means no: the agreement is shown.
#[must_use]
pub fn installer_acceptance_covers(
    record: Option<&InstallerAcceptance>,
    current_account: Option<&str>,
) -> bool {
    let (Some(record), Some(current)) = (record, current_account) else {
        return false;
    };
    record.version == CURRENT_EULA_VERSION
        && is_account_id(current)
        && record.account.eq_ignore_ascii_case(current)
}

/// The longest text form a security identifier can take.
const MAX_ACCOUNT_ID_LEN: usize = 184;
const MAX_SUB_AUTHORITIES: usize = 15;

/// `S-1-<authority>-<sub>…`: decimal parts only, each within its field's width.
fn is_account_id(text: &str) -> bool {
    if text.len() > MAX_ACCOUNT_ID_LEN {
        return false;
    }
    let Some(rest) = text
        .strip_prefix("S-1-")
        .or_else(|| text.strip_prefix("s-1-"))
    else {
        return false;
    };
    let mut parts = rest.split('-');
    let authority_fits = parts
        .next()
        .is_some_and(|part| decimal(part).is_some_and(|value| value < 1 << 48));
    let mut subs = 0;
    for part in parts {
        if decimal(part).is_none_or(|value| value > u64::from(u32::MAX)) {
            return false;
        }
        subs += 1;
    }
    authority_fits && (1..=MAX_SUB_AUTHORITIES).contains(&subs)
}

fn decimal(part: &str) -> Option<u64> {
    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    part.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const IVANOV: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";
    const PETROV: &str = "S-1-5-21-1004336348-1177238915-682003330-1002";

    fn installed_by(version: u32, account: &str) -> Option<InstallerAcceptance> {
        InstallerAcceptance::new(version, account)
    }

    #[test]
    fn the_account_that_accepted_in_the_installer_is_not_asked_again() {
        let record = installed_by(CURRENT_EULA_VERSION, IVANOV);
        assert!(installer_acceptance_covers(record.as_ref(), Some(IVANOV)));
    }

    #[test]
    fn another_account_on_the_same_computer_is_still_asked() {
        let record = installed_by(CURRENT_EULA_VERSION, IVANOV);
        assert!(!installer_acceptance_covers(record.as_ref(), Some(PETROV)));
    }

    /// An upgrade over an installation whose wizard showed an older text.
    #[test]
    fn an_older_agreement_accepted_in_the_installer_is_asked_again() {
        // The version before this one, or "never accepted" while there is none.
        for older in [CURRENT_EULA_VERSION.saturating_sub(1), EULA_NOT_ACCEPTED] {
            let record = installed_by(older, IVANOV);
            assert!(!installer_acceptance_covers(record.as_ref(), Some(IVANOV)));
        }
    }

    /// The owner's rule is "this exact version": a text this build never showed
    /// is not the one it asks about.
    #[test]
    fn a_different_agreement_version_is_asked_again() {
        let record = installed_by(CURRENT_EULA_VERSION + 1, IVANOV);
        assert!(!installer_acceptance_covers(record.as_ref(), Some(IVANOV)));
    }

    #[test]
    fn no_record_or_no_known_account_means_asked() {
        assert!(!installer_acceptance_covers(None, Some(IVANOV)));
        let record = installed_by(CURRENT_EULA_VERSION, IVANOV);
        assert!(!installer_acceptance_covers(record.as_ref(), None));
    }

    /// A damaged or hand-written value never stands for an account, and never
    /// panics: the agreement is shown instead.
    #[test]
    fn a_malformed_account_is_no_record() {
        for garbage in [
            "",
            " ",
            "S-1-",
            "S-1-5-",
            "S-1-5--21",
            "s-1-5-21-x",
            "S-1-5-21-1001\0",
            "S-1-5-21-1001 ",
            " S-1-5-21-1001",
            "Ivanov",
            "DOMAIN\\Ivanov",
            "S-1-5-21-\u{0661}\u{0662}",
            "S-1-5-21-99999999999999999999",
            "S-2-5-21-1001",
            "*",
        ] {
            assert_eq!(
                InstallerAcceptance::new(CURRENT_EULA_VERSION, garbage),
                None,
                "{garbage:?} taken for an account"
            );
            assert!(!installer_acceptance_covers(None, Some(garbage)));
        }
        let long = format!("S-1-5{}", "-1".repeat(200));
        assert_eq!(InstallerAcceptance::new(CURRENT_EULA_VERSION, &long), None);
    }

    /// A garbage current account does not match a garbage record either.
    #[test]
    fn a_malformed_current_account_never_matches() {
        let record = installed_by(CURRENT_EULA_VERSION, IVANOV);
        assert!(!installer_acceptance_covers(record.as_ref(), Some("")));
        assert!(!installer_acceptance_covers(
            record.as_ref(),
            Some(&format!("{IVANOV}-7"))
        ));
    }

    #[test]
    fn not_accepted_sentinel_requires_prompt() {
        assert!(!is_accepted(EULA_NOT_ACCEPTED));
    }

    #[test]
    fn current_version_is_accepted() {
        assert!(is_accepted(CURRENT_EULA_VERSION));
    }

    /// A stored acceptance of any older revision is asked again: holds the
    /// next bump to re-prompting, not only the never-accepted sentinel.
    #[test]
    fn every_older_revision_is_asked_again() {
        for older in 0..CURRENT_EULA_VERSION {
            assert!(!is_accepted(older), "revision {older} counted as current");
        }
    }

    #[test]
    fn a_future_acceptance_still_counts() {
        assert!(is_accepted(CURRENT_EULA_VERSION + 1));
    }
}
