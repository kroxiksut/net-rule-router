#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    nrr_shared::browser_dns_settings::fuzz_chromium_dns_mode(bytes);
});
