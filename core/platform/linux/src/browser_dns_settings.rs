//! Bounded settings hints; absent files never establish an effective browser mode.

use nrr_platform_api::browser_dns_settings::BrowserDnsSettingsPort;
use nrr_platform_api::enforcement::UserPrincipal;
use nrr_shared::browser_dns_settings::{
    read_chromium_dns_mode, BrowserDnsBrowser, BrowserDnsPolicy, BrowserDnsSettingsDto,
    BrowserDnsSource, MAX_BROWSER_DNS_SETTINGS_BYTES,
};

use crate::browser_history::{home_dir_of, Dir};

pub struct LinuxBrowserDnsSettings;

impl BrowserDnsSettingsPort for LinuxBrowserDnsSettings {
    fn inspect(&self, principal: &str) -> Vec<BrowserDnsSettingsDto> {
        let uid = (principal.len() <= 64 && principal.starts_with("unix:uid:"))
            .then(|| {
                UserPrincipal::from_stored(principal)
                    .ok()
                    .and_then(|p| p.as_unix_uid())
            })
            .flatten();
        let home =
            uid.and_then(|uid| home_dir_of(uid).and_then(|path| Dir::open_home(&path, uid).ok()));
        inspect_home(uid, home.as_ref())
    }
}

fn inspect_home(uid: Option<u32>, home: Option<&Dir>) -> Vec<BrowserDnsSettingsDto> {
    let mut observations = Vec::with_capacity(3);
    for (browser, location, policies) in [
        (
            BrowserDnsBrowser::Chrome,
            [".config", "google-chrome"],
            "/etc/opt/chrome/policies/managed",
        ),
        (
            BrowserDnsBrowser::Edge,
            [".config", "microsoft-edge"],
            "/etc/opt/edge/policies/managed",
        ),
    ] {
        let mut observation = BrowserDnsSettingsDto::unavailable(browser);
        observation.policy = managed_policy_hint(policies);
        if let (Some(uid), Some(home)) = (uid, home) {
            if let Ok(Some(file)) = home
                .open_path(&location, uid)
                .and_then(|dir| dir.open_file("Local State", uid, MAX_BROWSER_DNS_SETTINGS_BYTES))
            {
                if let Some(mode) = read_chromium_dns_mode(file) {
                    observation.configured_mode = mode;
                    observation.source = BrowserDnsSource::LocalState;
                }
            }
        }
        observations.push(observation);
    }
    observations.push(BrowserDnsSettingsDto::unsupported(
        BrowserDnsBrowser::Firefox,
    ));
    observations
}

fn managed_policy_hint(directory: &str) -> BrowserDnsPolicy {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return BrowserDnsPolicy::Unknown;
    };
    if entries
        .take(64)
        .flatten()
        .any(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
    {
        BrowserDnsPolicy::Detected
    } else {
        BrowserDnsPolicy::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt};

    #[test]
    fn a_browser_setting_symlink_cannot_read_another_profile() {
        let home = tempfile::tempdir().unwrap();
        let uid = home.path().metadata().unwrap().uid();
        let browser = home.path().join(".config/google-chrome");
        std::fs::create_dir_all(&browser).unwrap();
        let foreign = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(foreign.path(), br#"{"dns_over_https":{"mode":"secure"}}"#).unwrap();
        symlink(foreign.path(), browser.join("Local State")).unwrap();
        let home = Dir::open_home(home.path(), uid).unwrap();
        let observations = inspect_home(Some(uid), Some(&home));
        assert_eq!(observations[0].source, BrowserDnsSource::Unavailable);
        assert_eq!(
            observations[0].configured_mode,
            nrr_shared::browser_dns_settings::BrowserDnsMode::Unknown
        );
    }

    #[test]
    fn a_missing_or_non_linux_principal_never_reads_the_daemons_profile() {
        for principal in ["", "__baseline__", "mac:uid:0", "unix:uid:not-a-number"] {
            let observations = LinuxBrowserDnsSettings.inspect(principal);
            assert!(observations
                .iter()
                .all(|observation| observation.configured_mode
                    == nrr_shared::browser_dns_settings::BrowserDnsMode::Unknown));
        }
    }
}
