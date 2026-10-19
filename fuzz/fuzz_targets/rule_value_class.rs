#![no_main]
//! A rule value from a user-writable rules file: whatever the bytes, the
//! reading of its kind never panics, and a value is never sent away from the
//! section its own type names.

use libfuzzer_sys::fuzz_target;
use nrr_shared::app_identity::ExecutableNaming;
use nrr_shared::app_path::{AppPath, PathStyle};
use nrr_shared::preset_parser::ParsedRuleType;
use nrr_shared::rule_value_class::{classify_rule_value, misplaced_rule_value};

/// A match value is capped far below this; well above it keeps long inputs in.
const MAX_INPUT: usize = 64 * 1024;

const SECTIONS: [ParsedRuleType; 6] = [
    ParsedRuleType::Zone,
    ParsedRuleType::Domain,
    ParsedRuleType::ExactIp,
    ParsedRuleType::Subnet,
    ParsedRuleType::IpRange,
    ParsedRuleType::Application,
];

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let text = String::from_utf8_lossy(data);
    let own = classify_rule_value(&text).rule_type();
    for naming in [ExecutableNaming::WindowsExe, ExecutableNaming::AsNamed] {
        for section in SECTIONS {
            let target = misplaced_rule_value(section, &text, naming);
            assert_ne!(target, Some(section), "{text:?}");
            if target.is_some() {
                assert_eq!(target, own, "{text:?}");
            }
        }
    }
    for os in ["windows", "linux", "macos"] {
        let _ = nrr_client_logic::rule_value_class::app_value_form(&text, os);
    }
    // A path from a profile folder, resolved for owners as enforcement does.
    for style in [PathStyle::Windows, PathStyle::Linux, PathStyle::MacOS] {
        if let Ok(path) = AppPath::parse(&text, style) {
            for profile in [r"C:\Users\alice", "/home/alice", "relative", ""] {
                if let Ok(own) = path.for_profile(profile) {
                    assert!(own.profile_folder().is_none(), "{text:?}");
                }
            }
        }
    }
});
