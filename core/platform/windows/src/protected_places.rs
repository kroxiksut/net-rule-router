//! Windows mechanism behind
//! [`nrr_platform_api::protected_places::ProtectedPlacesSource`]: the folders
//! Windows registers (Known Folders, not a drive letter), the machine search
//! path from the machine environment key, the service's own search path and
//! our install folder. The static `C:` lists answer only when Windows cannot
//! name its own folder.

use std::path::Path;

use nrr_platform_api::protected_places::{
    add_own_install_folder, add_search_path_list, HostPlatform, ProtectedPlaces,
    ProtectedPlacesSource,
};

use crate::system_shell;

/// The production source; reads the machine once per call.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsProtectedPlaces;

impl ProtectedPlacesSource for WindowsProtectedPlaces {
    fn protected_places(&self) -> ProtectedPlaces {
        let mut places = match system_shell::windows_directory() {
            Some(windows) => registered_places(&windows),
            None => ProtectedPlaces::defaults(HostPlatform::Windows),
        };
        if let Some(path) = crate::machine_environment::machine_environment().get("Path") {
            add_search_path_list(&mut places, path, ';');
        }
        // What the service itself runs programs from.
        if let Ok(path) = std::env::var("PATH") {
            add_search_path_list(&mut places, &path, ';');
        }
        add_own_install_folder(&mut places);
        places
    }
}

/// The lists, built from the folders the shell registers.
fn registered_places(windows: &Path) -> ProtectedPlaces {
    let text = |path: &Path| path.to_string_lossy().into_owned();
    let mut places = ProtectedPlaces::empty(HostPlatform::Windows);
    places.add_system_folder(&text(windows));
    // The Windows folder is on the search path of every machine, whatever the
    // registry says today.
    for sub in [
        "",
        "System32",
        r"System32\Wbem",
        r"System32\WindowsPowerShell\v1.0",
    ] {
        places.add_search_path_folder(&text(&windows.join(sub)));
    }
    for program_files in system_shell::program_files_directories() {
        places.add_shared_folder(&text(&program_files));
        for defender in [
            "Windows Defender",
            "Windows Defender Advanced Threat Protection",
        ] {
            places.add_system_folder(&text(&program_files.join(defender)));
        }
    }
    if let Some(program_data) = system_shell::program_data_directory() {
        places.add_shared_folder(&text(&program_data));
        for defender in [
            r"Microsoft\Windows Defender",
            r"Microsoft\Windows Defender Advanced Threat Protection",
        ] {
            places.add_system_folder(&text(&program_data.join(defender)));
        }
    }
    if let Some(users) = system_shell::user_profiles_directory() {
        places.add_shared_folder(&text(&users));
        places.add_shared_folder(&text(&users.join("*")));
    }
    if let Some(public) = system_shell::public_directory() {
        places.add_shared_folder(&text(&public));
    }
    // IIS installs its site root on the system drive; no Known Folder names it.
    if let Some(drive) = text(windows).get(..2) {
        places.add_shared_folder(&format!(r"{drive}\inetpub"));
        places.add_shared_folder(&format!(r"{drive}\inetpub\wwwroot"));
    }
    places
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::protected_places::{
        protection_verdict, AppTarget, ProtectionReason, ProtectionVerdict, RuleEffect,
    };

    #[test]
    fn this_machines_registered_folders_are_protected() {
        let places = WindowsProtectedPlaces.protected_places();
        let deny = |target: AppTarget<'_>| protection_verdict(target, RuleEffect::Deny, &places);
        let windows = system_shell::windows_directory().expect("windows folder");
        assert_eq!(
            deny(AppTarget::FolderTree(&windows.to_string_lossy())),
            ProtectionVerdict::Refused(ProtectionReason::SystemFolder)
        );
        for program_files in system_shell::program_files_directories() {
            assert_eq!(
                deny(AppTarget::FolderTree(&program_files.to_string_lossy())),
                ProtectionVerdict::Refused(ProtectionReason::SharedFolder),
                "{}",
                program_files.display()
            );
            let app = program_files.join("Example App");
            assert_eq!(
                deny(AppTarget::FolderTree(&app.to_string_lossy())),
                ProtectionVerdict::Allowed
            );
        }
        let curl = system_shell::system32_exe("curl.exe");
        assert_eq!(
            deny(AppTarget::File(&curl.to_string_lossy())),
            ProtectionVerdict::Warn(ProtectionReason::FileInSystemFolder)
        );
    }
}
