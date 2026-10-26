#![no_main]
//! A preset file as imported: the byte-level validation pipeline and the
//! canonical-text parser the clients and the service share, and the rules
//! a table reads out of another OS's section.

use libfuzzer_sys::fuzz_target;
use nrr_domain::preset_validation::validate_preset_bytes;
use nrr_shared::preset_parser::{other_os_app_rules, parse_canonical_rules};

const MAX_FILE: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FILE {
        return;
    }
    let _ = validate_preset_bytes(data);
    let text = String::from_utf8_lossy(data);
    let parsed = parse_canonical_rules(&text);
    // Another OS's section, as a table reads it out of the carried text.
    for block in &parsed.passthrough {
        let _ = other_os_app_rules(&block.section_name, &block.raw_text);
    }
});
