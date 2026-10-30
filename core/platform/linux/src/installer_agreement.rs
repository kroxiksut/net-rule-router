//! Linux implementation of [`InstallerAgreementPort`]: the `.deb`, `.rpm` and
//! archive installers show no agreement, so there is never a record and every
//! account is asked at its first start.

use nrr_platform_api::installer_agreement::InstallerAgreementPort;
use nrr_shared::eula::InstallerAcceptance;

pub struct LinuxInstallerAgreement;

impl InstallerAgreementPort for LinuxInstallerAgreement {
    fn recorded(&self) -> Option<InstallerAcceptance> {
        None
    }

    fn current_account(&self) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_account_is_asked_on_linux() {
        assert!(
            !nrr_platform_api::installer_agreement::accepted_in_installer(&LinuxInstallerAgreement)
        );
    }
}
