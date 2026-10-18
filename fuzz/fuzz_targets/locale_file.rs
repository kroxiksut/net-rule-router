#![no_main]
//! A locale file from the user's locales folder: the size bound, the parse,
//! validation and the merge with the bundled baseline never panic, and what
//! comes out stays bounded by what went in.

use libfuzzer_sys::fuzz_target;
use nrr_shared::localization::fuzz_user_locale_file;

/// The first byte picks the file name, so the id the metadata must match
/// varies too.
const IDS: [&str; 3] = ["ru", "en", "pt_BR.UTF-8"];

fuzz_target!(|data: &[u8]| {
    let (head, body) = data.split_first().map_or((0, data), |(h, b)| (*h, b));
    let id = IDS[usize::from(head) % IDS.len()];
    let keys = fuzz_user_locale_file(id, body);
    // Each key needs at least a few bytes of the file; the baseline adds one.
    assert!(keys <= body.len() + 2);
});
