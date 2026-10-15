#![no_main]
//! A preset file as imported: the byte-level validation pipeline and the
//! canonical-text parser the clients and the service share.

use libfuzzer_sys::fuzz_target;
use nrr_domain::preset_validation::validate_preset_bytes;
use nrr_shared::preset_parser::parse_canonical_rules;

const MAX_FILE: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FILE {
        return;
    }
    let _ = validate_preset_bytes(data);
    let text = String::from_utf8_lossy(data);
    let _ = parse_canonical_rules(&text);
});
