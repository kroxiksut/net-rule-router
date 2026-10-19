#![no_main]
//! An application value from a user-writable rules file, and the search-path
//! lists a machine reports: whatever the bytes, the protection's verdict never
//! panics, says the same twice, and a path that climbs with `..` never slips
//! past it. The same bytes as the program names a folder holds: what a
//! confirmation names stays bounded.

use libfuzzer_sys::fuzz_target;
use nrr_domain::protected_places::{
    critical_processes_covered, protection_verdict, AppTarget, ProtectedPlaces,
    ProtectionVerdict, RuleEffect, MAX_CRITICAL_NAMED,
};
use nrr_domain::rules_file::HostPlatform;
use nrr_platform_api::protected_places::{
    add_search_path_list, etc_paths_entries, login_defs_search_paths,
};

/// A match value is capped far below this; well above it keeps long inputs in.
const MAX_INPUT: usize = 64 * 1024;

const PLATFORMS: [HostPlatform; 3] = [HostPlatform::Windows, HostPlatform::Linux, HostPlatform::MacOS];
const EFFECTS: [RuleEffect; 3] = [
    RuleEffect::Deny,
    RuleEffect::PrimaryRoute,
    RuleEffect::SecondaryRoute,
];

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let text = String::from_utf8_lossy(data);
    for platform in PLATFORMS {
        let climbs = match platform {
            HostPlatform::Windows => text.split(['/', '\\']).any(|segment| segment == ".."),
            HostPlatform::Linux | HostPlatform::MacOS => text.split('/').any(|segment| segment == ".."),
        };
        let mut places = ProtectedPlaces::defaults(platform);
        add_search_path_list(&mut places, &text, ':');
        add_search_path_list(&mut places, &text, ';');
        for list in login_defs_search_paths(&text) {
            add_search_path_list(&mut places, list, ':');
        }
        for entry in etc_paths_entries(&text) {
            places.add_search_path_folder(entry);
        }
        places.add_own_folder(&text);
        for effect in EFFECTS {
            for target in [
                AppTarget::Name(&text),
                AppTarget::NameGlob(&text),
                AppTarget::File(&text),
                AppTarget::Folder(&text),
                AppTarget::FolderTree(&text),
            ] {
                let verdict = protection_verdict(target, effect, &places);
                assert_eq!(verdict, protection_verdict(target, effect, &places));
                let programs: Vec<&str> = text.lines().take(4096).collect();
                let critical = critical_processes_covered(target, &programs, platform);
                assert!(critical.len() <= MAX_CRITICAL_NAMED);
                assert!(critical.windows(2).all(|w| w[0] < w[1]), "{critical:?}");
                let is_path = !matches!(target, AppTarget::Name(_) | AppTarget::NameGlob(_));
                if is_path && climbs {
                    assert!(
                        matches!(verdict, ProtectionVerdict::Refused(_)),
                        "{text:?} {target:?} {effect:?}"
                    );
                }
            }
        }
    }
});
