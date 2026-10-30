//! What an installer recorded about the end-user agreement accepted on its
//! licence page, behind a port: where an installer keeps it is OS mechanism.
//!
//! Not a security gate. The record only spares the one account that accepted
//! a second reading; its trust rests on where the record lives (a place only
//! administrators can change) and on the account check, never on its presence.

use nrr_shared::eula::{installer_acceptance_covers, InstallerAcceptance};

pub trait InstallerAgreementPort: Send + Sync {
    /// The installer's record; `None` when there is none or it does not read
    /// as one.
    fn recorded(&self) -> Option<InstallerAcceptance>;

    /// The account this process runs as, in the form the installer records.
    fn current_account(&self) -> Option<String>;
}

/// Where no installer shows the agreement (the Linux packages): every account
/// is asked at its first start.
pub struct NoInstallerAgreement;

impl InstallerAgreementPort for NoInstallerAgreement {
    fn recorded(&self) -> Option<InstallerAcceptance> {
        None
    }

    fn current_account(&self) -> Option<String> {
        None
    }
}

/// Whether this account already accepted the current agreement in the
/// installer. The account is looked up only when there is a record.
pub fn accepted_in_installer(port: &dyn InstallerAgreementPort) -> bool {
    let Some(record) = port.recorded() else {
        return false;
    };
    installer_acceptance_covers(Some(&record), port.current_account().as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_shared::eula::CURRENT_EULA_VERSION;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Recorded {
        record: Option<InstallerAcceptance>,
        account: Option<&'static str>,
        asked_account: AtomicBool,
    }

    impl InstallerAgreementPort for Recorded {
        fn recorded(&self) -> Option<InstallerAcceptance> {
            self.record.clone()
        }
        fn current_account(&self) -> Option<String> {
            self.asked_account.store(true, Ordering::SeqCst);
            self.account.map(str::to_owned)
        }
    }

    const IVANOV: &str = "S-1-5-21-1-2-3-1001";

    #[test]
    fn a_host_whose_installer_shows_no_agreement_asks_every_account() {
        assert!(!accepted_in_installer(&NoInstallerAgreement));
    }

    #[test]
    fn the_record_counts_only_for_the_account_it_names() {
        let port = |account| Recorded {
            record: InstallerAcceptance::new(CURRENT_EULA_VERSION, IVANOV),
            account,
            asked_account: AtomicBool::new(false),
        };
        assert!(accepted_in_installer(&port(Some(IVANOV))));
        assert!(!accepted_in_installer(&port(Some("S-1-5-21-1-2-3-1002"))));
        assert!(!accepted_in_installer(&port(None)));
    }

    /// Every start without a record pays nothing for the account lookup.
    #[test]
    fn without_a_record_the_account_is_not_looked_up() {
        let port = Recorded {
            record: None,
            account: Some(IVANOV),
            asked_account: AtomicBool::new(false),
        };
        assert!(!accepted_in_installer(&port));
        assert!(!port.asked_account.load(Ordering::SeqCst));
    }
}
