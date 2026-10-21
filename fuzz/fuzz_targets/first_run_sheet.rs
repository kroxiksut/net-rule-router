#![no_main]
//! The installer's first-run answer sheet, read from a folder other local
//! accounts may be able to write to.

use libfuzzer_sys::fuzz_target;
use nrr_shared::first_run_sheet::{parse_sheet, MAX_SHEET_BYTES};

fuzz_target!(|data: &[u8]| {
    // The file reader never hands the parser more than one byte over the bound.
    if data.len() as u64 > MAX_SHEET_BYTES + 1 {
        return;
    }
    if let Ok(answers) = parse_sheet(data) {
        let _ = answers.completes_first_run();
    }
});
