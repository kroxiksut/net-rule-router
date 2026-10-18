//! Linux mechanism behind
//! [`nrr_platform_api::protected_places::ProtectedPlacesSource`]: the static
//! lists, the search paths `/etc/login.defs` gives users and root, the
//! service's own `PATH` and our install folder.

use std::path::Path;

use nrr_platform_api::protected_places::{
    add_own_install_folder, add_search_path_list, login_defs_search_paths, read_config_text,
    HostPlatform, ProtectedPlaces, ProtectedPlacesSource,
};

const LOGIN_DEFS: &str = "/etc/login.defs";

/// The production source; reads the machine once per call.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxProtectedPlaces;

impl ProtectedPlacesSource for LinuxProtectedPlaces {
    fn protected_places(&self) -> ProtectedPlaces {
        let mut places = ProtectedPlaces::defaults(HostPlatform::Linux);
        if let Some(text) = read_config_text(Path::new(LOGIN_DEFS)) {
            for list in login_defs_search_paths(&text) {
                add_search_path_list(&mut places, list, ':');
            }
        }
        if let Ok(path) = std::env::var("PATH") {
            add_search_path_list(&mut places, &path, ':');
        }
        add_own_install_folder(&mut places);
        places
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::protected_places::{
        protection_verdict, AppTarget, ProtectionReason, ProtectionVerdict, RuleEffect,
    };

    #[test]
    fn the_system_folders_are_protected_whatever_the_machine_adds() {
        let places = LinuxProtectedPlaces.protected_places();
        assert_eq!(
            protection_verdict(AppTarget::Folder("/usr/bin"), RuleEffect::Deny, &places),
            ProtectionVerdict::Refused(ProtectionReason::SystemFolder)
        );
        assert_eq!(
            protection_verdict(
                AppTarget::FolderTree("/usr/lib/firefox"),
                RuleEffect::SecondaryRoute,
                &places
            ),
            ProtectionVerdict::Allowed
        );
    }
}
