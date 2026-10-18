//! `ProtectedPlacesSource` platform port: where this machine keeps the
//! programs a rule may not deny or send over the additional route.
//!
//! The decision is `nrr_domain::protected_places`; a port only says which
//! folders are the system's, which are shared, which make up the system search
//! path and where we are installed. The default answers the per-OS static
//! lists plus our install folder, so a platform without an implementation still
//! refuses `/`, `/usr/bin` or `C:\Windows`.
//!
//! The helpers below read values another party may have shaped (a search path,
//! `/etc/login.defs`, `/etc/paths`): they only split text, never panic, and
//! stop at [`MAX_LIST_ENTRIES`] entries; each folder is then bounded by the
//! domain's own limits.

use std::path::Path;

pub use nrr_domain::protected_places::{
    protection_verdict, AppTarget, ProtectedPlaces, ProtectionReason, ProtectionVerdict, RuleEffect,
};
pub use nrr_domain::rules_file::HostPlatform;

/// Entries one list may contribute; past it the rest is ignored.
pub const MAX_LIST_ENTRIES: usize = nrr_domain::protected_places::MAX_PLACES_PER_LIST;

/// Most bytes of a configuration file a reader looks at.
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;

/// The machine's protected folders, read once when the service starts.
pub trait ProtectedPlacesSource: Send + Sync {
    fn protected_places(&self) -> ProtectedPlaces;
}

/// The per-OS static lists of the platform this build runs on, plus our
/// install folder.
#[derive(Debug, Default, Clone, Copy)]
pub struct StaticProtectedPlaces;

impl ProtectedPlacesSource for StaticProtectedPlaces {
    fn protected_places(&self) -> ProtectedPlaces {
        let mut places = ProtectedPlaces::defaults(HostPlatform::compiled());
        add_own_install_folder(&mut places);
        places
    }
}

/// Adds the folder the running binary sits in as ours.
pub fn add_own_install_folder(places: &mut ProtectedPlaces) {
    if let Some(dir) = std::env::current_exe()
        .ok()
        .as_deref()
        .and_then(Path::parent)
    {
        places.add_own_folder(&dir.to_string_lossy());
    }
}

/// Adds every folder of a search-path value (`PATH`): entries split by
/// `separator`, surrounding quotes and blanks dropped, empty and relative ones
/// ignored by the domain.
pub fn add_search_path_list(places: &mut ProtectedPlaces, list: &str, separator: char) {
    for entry in list.split(separator).take(MAX_LIST_ENTRIES) {
        let entry = entry.trim().trim_matches('"').trim();
        if !entry.is_empty() {
            places.add_search_path_folder(entry);
        }
    }
}

/// The `PATH` values `/etc/login.defs` gives users and root: the words after
/// `ENV_PATH` and `ENV_SUPATH`, with their `PATH=` prefix dropped.
#[must_use]
pub fn login_defs_search_paths(text: &str) -> Vec<&str> {
    text.lines()
        .take(MAX_LIST_ENTRIES * 16)
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let key = words.next()?;
            if key != "ENV_PATH" && key != "ENV_SUPATH" {
                return None;
            }
            let value = words.next()?;
            Some(value.strip_prefix("PATH=").unwrap_or(value))
        })
        .take(MAX_LIST_ENTRIES)
        .collect()
}

/// The folders `/etc/paths` lists, one per line; `#` starts a comment.
#[must_use]
pub fn etc_paths_entries(text: &str) -> Vec<&str> {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .filter(|line| !line.is_empty())
        .take(MAX_LIST_ENTRIES)
        .collect()
}

/// A configuration file's text, at most [`MAX_CONFIG_BYTES`] of it; `None`
/// when it cannot be read. Invalid UTF-8 is replaced, not refused: a stray
/// byte in a comment must not hide the lines that matter.
#[must_use]
pub fn read_config_text(path: &Path) -> Option<String> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_defs_gives_both_search_paths() {
        let text = "# comment\nENV_SUPATH\tPATH=/usr/local/sbin:/usr/sbin\nENV_PATH PATH=/usr/local/bin:/usr/bin\nENV_PATHX nothing\nENV_PATH\n";
        assert_eq!(
            login_defs_search_paths(text),
            ["/usr/local/sbin:/usr/sbin", "/usr/local/bin:/usr/bin"]
        );
        assert!(login_defs_search_paths("").is_empty());
    }

    #[test]
    fn etc_paths_lists_one_folder_per_line() {
        assert_eq!(
            etc_paths_entries("/usr/local/bin\n# x\n\n/usr/bin # y\n"),
            ["/usr/local/bin", "/usr/bin"]
        );
    }

    #[test]
    fn a_search_path_value_adds_its_absolute_folders() {
        let mut places = ProtectedPlaces::empty(HostPlatform::Linux);
        add_search_path_list(&mut places, "/opt/tool/bin::relative:/srv/x/bin", ':');
        let refused =
            |folder: &str| protection_verdict(AppTarget::Folder(folder), RuleEffect::Deny, &places);
        assert_eq!(
            refused("/opt/tool/bin"),
            ProtectionVerdict::Refused(ProtectionReason::SearchPathFolder)
        );
        assert_eq!(
            refused("/srv/x/bin"),
            ProtectionVerdict::Refused(ProtectionReason::SearchPathFolder)
        );
        assert_eq!(refused("/opt/tool"), ProtectionVerdict::Allowed);

        let mut windows = ProtectedPlaces::empty(HostPlatform::Windows);
        add_search_path_list(&mut windows, r#" "C:\Tools\bin" ;C:\Other;"#, ';');
        assert_eq!(
            protection_verdict(
                AppTarget::Folder(r"c:\tools\BIN"),
                RuleEffect::Deny,
                &windows
            ),
            ProtectionVerdict::Refused(ProtectionReason::SearchPathFolder)
        );
    }

    #[test]
    fn the_static_source_knows_our_install_folder() {
        let places = StaticProtectedPlaces.protected_places();
        let exe = std::env::current_exe().expect("current exe");
        let verdict = protection_verdict(
            AppTarget::File(&exe.to_string_lossy()),
            RuleEffect::Deny,
            &places,
        );
        assert_eq!(
            verdict,
            ProtectionVerdict::Refused(ProtectionReason::OwnProgram)
        );
    }
}
