#![no_main]
//! A rules file from a user-writable folder: the parse, the canonicalisation
//! into a rule set for either host platform, and the stored JSON form.

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
    for platform in [HostPlatform::Windows, HostPlatform::Linux] {
        let _ = canonicalize_preset_rules(&outcome, RouteRole::Primary, platform, false);
        let _ = canonicalize_preset_rules(&outcome, RouteRole::Secondary, platform, true);
    }
    let _ = nrr_shared::rules_json::from_canonical_string(&text);
});
