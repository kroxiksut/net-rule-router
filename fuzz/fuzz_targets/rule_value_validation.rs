#![no_main]
//! A rule value as a client sends it over IPC before any book is parsed:
//! judging it never panics, for every type, effect and platform's protected
//! folders, and a protected-folder verdict only ever narrows a valid value.

use libfuzzer_sys::fuzz_target;
use nrr_domain::protected_places::{ProtectedPlaces, RuleEffect};
use nrr_domain::rule_value_validation::{validate_rule_value, validate_rule_value_in};
use nrr_domain::rules_file::HostPlatform;

/// Well above the per-value cap of a rules file, so the bound itself is reached.
const MAX_INPUT: usize = 4 * 1024;

const SLUGS: [&str; 7] = [
    "zone",
    "domain",
    "exact-ip",
    "subnet",
    "ip-range",
    "application",
    "bogus",
];
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
    for platform in [
        HostPlatform::Windows,
        HostPlatform::Linux,
        HostPlatform::MacOS,
    ] {
        let places = ProtectedPlaces::defaults(platform);
        for slug in SLUGS {
            let plain = validate_rule_value(slug, &text);
            for effect in EFFECTS {
                let judged = validate_rule_value_in(slug, &text, effect, &places);
                if plain.is_error() {
                    assert!(judged.is_error(), "{slug} {text:?}");
                }
                if slug != "application" {
                    assert_eq!(judged.is_error(), plain.is_error(), "{slug} {text:?}");
                }
            }
        }
    }
});
