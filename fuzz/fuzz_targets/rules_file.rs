#![no_main]
//! A rules file from a user-writable folder: the parse, the canonicalisation
//! into a rule set for every host platform, the stored JSON form, and a path
//! rule matched against an image path another process could report.

use libfuzzer_sys::fuzz_target;
use nrr_domain::preset_canonicalize::canonicalize_preset_rules;
use nrr_domain::rules_file::{parse_rules_file, HostPlatform};
use nrr_shared::RouteRole;

/// A rules file is read whole; the import limit bounds it.
const MAX_FILE: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FILE {
        return;
    }
    let text = String::from_utf8_lossy(data);
    let outcome = parse_rules_file(&text);
    for platform in [HostPlatform::Windows, HostPlatform::Linux, HostPlatform::MacOS] {
        let _ = canonicalize_preset_rules(&outcome, RouteRole::Primary, platform, false);
        let routed = canonicalize_preset_rules(&outcome, RouteRole::Secondary, platform, true);
        let paths = routed
            .rule_set()
            .into_iter()
            .flat_map(|set| set.rules())
            .filter_map(|rule| rule.app_match.as_ref()?.pattern.path());
        for path in paths {
            let _ = path.match_image(&text);
        }
    }
    let _ = nrr_shared::rules_json::from_canonical_string(&text);
});
