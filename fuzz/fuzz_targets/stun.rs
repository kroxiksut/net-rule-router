#![no_main]
//! A STUN binding response from any host on the path.

use libfuzzer_sys::fuzz_target;
use nrr_platform_api::external_ip::{parse_binding_response, TransactionId};

fuzz_target!(|data: &[u8]| {
    if data.len() > 1500 {
        return;
    }
    // The id the datagram itself carries reaches the attribute walk; a fixed
    // one exercises the mismatch exit.
    let mut carried: TransactionId = [0; 12];
    if let Some(bytes) = data.get(8..20) {
        carried.copy_from_slice(bytes);
    }
    let _ = parse_binding_response(data, &carried);
    let _ = parse_binding_response(data, &[0xA5; 12]);
});
