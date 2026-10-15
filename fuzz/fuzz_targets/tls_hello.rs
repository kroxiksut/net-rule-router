#![no_main]
//! The first bytes a peer sends back after our ClientHello, and the name that
//! goes into the hello.

use libfuzzer_sys::fuzz_target;
use nrr_service_runtime::tls_hello;

fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 {
        return;
    }
    let _ = tls_hello::classify_first_record(data);
    let name = String::from_utf8_lossy(data);
    let _ = tls_hello::client_hello(&name, &[0x11; 32], &[0x22; 32], &[0x33; 32]);
});
