#![no_main]
//! One message from the system bus connection that follows logind: the frame
//! length, the header-field walk, the reply match and the signal decoder. Any
//! local process can address a message to that connection.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > nrr_platform_linux::logind_signals::MAX_KEPT_MESSAGE {
        return;
    }
    let _ = nrr_platform_linux::logind_signals::fuzz_frame(data);
});
