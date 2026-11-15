#![no_main]

use libfuzzer_sys::fuzz_target;
use nrr_browser_native_host::fuzz::{native_stream, MAX_MESSAGE_SIZE};

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > MAX_MESSAGE_SIZE {
        return;
    }
    native_stream(bytes);
    let mut framed = (bytes.len() as u32).to_ne_bytes().to_vec();
    framed.extend_from_slice(bytes);
    native_stream(&framed);
});
