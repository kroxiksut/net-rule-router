#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    nrr_diagnostics::archive::fuzz_archive_correlation(data);
});
